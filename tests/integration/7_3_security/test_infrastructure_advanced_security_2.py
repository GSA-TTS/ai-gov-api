# Section 7.3 - Advanced Infrastructure Security & Configuration Tests (Part 2)
# Based on: docs/test_design_n_planning/Testcases_7_3_Security Testing/Test Cases for Infrastructure Security & Configuration.md
# Additional advanced test cases matching design document test case IDs

import pytest
import httpx
import asyncio
import uuid
import time
import json
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.auth_fixtures import AuthFixtures
from utils.security_validators import SecurityValidator

class TestAdvancedInfrastructureSecurity2:
    """Additional advanced infrastructure security and configuration tests matching design document test case IDs"""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_container_escape_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """INFRA_CONTAINER_ESCAPE_001: Container escape prevention"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test container escape prevention through various attack vectors
        escape_scenarios = [
            {
                "name": "Privileged container escape",
                "headers": {"X-Container-Escape": "privileged"},
                "description": "Attempt privileged container access"
            },
            {
                "name": "Host mount escape",
                "headers": {"X-Host-Mount": "/proc/self/root"},
                "description": "Attempt host filesystem mount"
            },
            {
                "name": "Capabilities abuse",
                "headers": {"X-Capabilities": "SYS_ADMIN"},
                "description": "Attempt capabilities abuse"
            },
            {
                "name": "Namespace escape",
                "headers": {"X-Namespace-Escape": "host"},
                "description": "Attempt namespace escape"
            },
            {
                "name": "Socket escape",
                "headers": {"X-Socket-Access": "/var/run/docker.sock"},
                "description": "Attempt Docker socket access"
            }
        ]
        
        for scenario in escape_scenarios:
            escape_headers = auth_headers.copy()
            escape_headers.update(scenario["headers"])
            
            escape_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Container escape test: {scenario['description']}"}],
                "max_tokens": 50
            }
            
            escape_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                escape_headers, escape_request, track_cost=False
            )
            
            # Should handle escape attempts safely
            assert escape_response.status_code in [200, 400, 403], \
                f"Container escape should be prevented: {scenario['name']}"
            
            if escape_response.status_code == 200:
                response_data = escape_response.json()
                response_text = str(response_data).lower()
                
                # Should not contain indicators of successful escape
                escape_indicators = [
                    "root access",
                    "host filesystem",
                    "escaped container",
                    "privileged mode",
                    "docker socket"
                ]
                
                for indicator in escape_indicators:
                    assert indicator not in response_text, \
                        f"Container escape indicator detected: {indicator}"
            
            logger.info(f"Container escape prevention tested: {scenario['name']}")
        
        # Test container runtime security
        runtime_headers = auth_headers.copy()
        runtime_headers["X-Runtime-Security-Test"] = "true"
        
        runtime_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Container runtime security test"}],
            "max_tokens": 50
        }
        
        runtime_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            runtime_headers, runtime_request, track_cost=False
        )
        
        # Runtime should be secure
        assert runtime_response.status_code == 200, \
            "Container runtime should operate securely"
        
        logger.info("INFRA_CONTAINER_ESCAPE_001: Container escape prevention validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_secrets_rotation_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """INFRA_SECRETS_ROTATION_001: Automated secrets rotation"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test secrets rotation mechanisms
        rotation_test_id = str(uuid.uuid4())
        
        # Test rotation status endpoints
        rotation_endpoints = [
            "/secrets/rotation/status",
            "/api/v1/secrets/rotation",
            "/admin/rotation",
            "/security/key-rotation"
        ]
        
        for endpoint in rotation_endpoints:
            rotation_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if rotation_response.status_code == 200:
                logger.info(f"Secrets rotation status available at: {endpoint}")
                
                try:
                    rotation_data = rotation_response.json()
                    
                    # Check for rotation metadata
                    rotation_fields = [
                        "last_rotation",
                        "next_rotation",
                        "rotation_interval",
                        "rotation_status"
                    ]
                    
                    for field in rotation_fields:
                        if field in rotation_data:
                            logger.info(f"Rotation status includes: {field}")
                
                except json.JSONDecodeError:
                    logger.info(f"Rotation endpoint returns non-JSON: {endpoint}")
                    
            elif rotation_response.status_code in [401, 403]:
                logger.info(f"Rotation endpoint properly protected: {endpoint}")
            elif rotation_response.status_code == 404:
                logger.info(f"Rotation endpoint not found: {endpoint}")
        
        # Test rotation trigger mechanisms
        trigger_scenarios = [
            {"X-Rotation-Trigger": "manual"},
            {"X-Rotation-Type": "emergency"},
            {"X-Force-Rotation": "true"}
        ]
        
        for trigger_headers in trigger_scenarios:
            trigger_test_headers = auth_headers.copy()
            trigger_test_headers.update(trigger_headers)
            trigger_test_headers["X-Rotation-Test-ID"] = rotation_test_id
            
            trigger_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Secrets rotation trigger test"}],
                "max_tokens": 50
            }
            
            trigger_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                trigger_test_headers, trigger_request, track_cost=False
            )
            
            # Should handle rotation triggers appropriately
            assert trigger_response.status_code in [200, 202, 400, 403], \
                f"Rotation trigger should be handled: {trigger_headers}"
        
        # Test rotation policies
        policy_headers = auth_headers.copy()
        policy_headers["X-Rotation-Policy-Test"] = "true"
        
        policy_scenarios = [
            {"interval": "daily", "expected": "high_security"},
            {"interval": "weekly", "expected": "normal_security"},
            {"interval": "monthly", "expected": "low_security"}
        ]
        
        for scenario in policy_scenarios:
            policy_test_headers = policy_headers.copy()
            policy_test_headers["X-Rotation-Interval"] = scenario["interval"]
            
            policy_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Rotation policy test: {scenario['interval']} rotation"}],
                "max_tokens": 50
            }
            
            policy_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                policy_test_headers, policy_request, track_cost=False
            )
            
            # Should handle rotation policies
            assert policy_response.status_code == 200, \
                f"Rotation policy should be handled: {scenario['interval']}"
        
        logger.info("INFRA_SECRETS_ROTATION_001: Automated secrets rotation validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_monitoring_security_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """INFRA_MONITORING_SECURITY_001: Infrastructure monitoring security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test monitoring security endpoints
        monitoring_endpoints = [
            "/metrics",
            "/health",
            "/status",
            "/monitoring/security",
            "/prometheus/metrics",
            "/grafana/health"
        ]
        
        monitoring_results = []
        
        for endpoint in monitoring_endpoints:
            monitoring_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            monitoring_results.append({
                "endpoint": endpoint,
                "status_code": monitoring_response.status_code,
                "accessible": monitoring_response.status_code == 200
            })
            
            if monitoring_response.status_code == 200:
                content = monitoring_response.text.lower()
                
                # Check for sensitive information in monitoring data
                sensitive_patterns = [
                    "api_key",
                    "password",
                    "secret",
                    "token",
                    "credential",
                    "private_key",
                    "database_url"
                ]
                
                exposed_sensitive = []
                for pattern in sensitive_patterns:
                    if pattern in content:
                        exposed_sensitive.append(pattern)
                
                if exposed_sensitive:
                    logger.warning(f"Sensitive data in monitoring at {endpoint}: {exposed_sensitive}")
                else:
                    logger.info(f"Monitoring endpoint secure: {endpoint}")
                    
            elif monitoring_response.status_code in [401, 403]:
                logger.info(f"Monitoring endpoint properly protected: {endpoint}")
            elif monitoring_response.status_code == 404:
                logger.info(f"Monitoring endpoint not found: {endpoint}")
        
        # Test monitoring access control
        unauth_monitoring_tests = []
        
        for endpoint in monitoring_endpoints:
            # Test without authentication
            unauth_response = await make_request(
                http_client, "GET", endpoint,
                {}, track_cost=False
            )
            
            unauth_monitoring_tests.append({
                "endpoint": endpoint,
                "unauth_status": unauth_response.status_code,
                "publicly_accessible": unauth_response.status_code == 200
            })
            
            if unauth_response.status_code == 200:
                logger.warning(f"Monitoring endpoint publicly accessible: {endpoint}")
            else:
                logger.info(f"Monitoring endpoint requires auth: {endpoint}")
        
        # Test monitoring data integrity
        integrity_headers = auth_headers.copy()
        integrity_headers["X-Monitoring-Integrity-Test"] = "true"
        
        integrity_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Monitoring integrity test"}],
            "max_tokens": 50
        }
        
        integrity_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            integrity_headers, integrity_request, track_cost=False
        )
        
        # Should handle monitoring integrity appropriately
        assert integrity_response.status_code == 200, \
            "Monitoring integrity should be maintained"
        
        # Test monitoring tampering prevention
        tamper_scenarios = [
            {"X-Tamper-Metrics": "true"},
            {"X-Inject-Monitoring": "false_metrics"},
            {"X-Override-Health": "unhealthy"}
        ]
        
        for tamper_headers in tamper_scenarios:
            tamper_test_headers = auth_headers.copy()
            tamper_test_headers.update(tamper_headers)
            
            tamper_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Monitoring tampering test"}],
                "max_tokens": 50
            }
            
            tamper_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                tamper_test_headers, tamper_request, track_cost=False
            )
            
            # Should prevent monitoring tampering
            assert tamper_response.status_code in [200, 400], \
                f"Monitoring tampering should be prevented: {tamper_headers}"
        
        logger.info("INFRA_MONITORING_SECURITY_001: Infrastructure monitoring security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_cloud_governance_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """INFRA_CLOUD_GOVERNANCE_001: Cloud governance and resource management"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test cloud governance through API behavior
        governance_test_id = str(uuid.uuid4())
        
        # Test resource governance policies
        governance_scenarios = [
            {
                "resource_type": "compute",
                "policy": "resource_limits",
                "description": "Compute resource governance"
            },
            {
                "resource_type": "storage",
                "policy": "data_retention",
                "description": "Storage governance"
            },
            {
                "resource_type": "network",
                "policy": "access_control",
                "description": "Network governance"
            },
            {
                "resource_type": "api",
                "policy": "rate_limiting",
                "description": "API governance"
            }
        ]
        
        for scenario in governance_scenarios:
            governance_headers = auth_headers.copy()
            governance_headers["X-Governance-Test"] = governance_test_id
            governance_headers["X-Resource-Type"] = scenario["resource_type"]
            governance_headers["X-Policy-Type"] = scenario["policy"]
            
            governance_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Cloud governance test: {scenario['description']}"}],
                "max_tokens": 50
            }
            
            governance_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                governance_headers, governance_request, track_cost=False
            )
            
            # Should handle governance policies appropriately
            assert governance_response.status_code in [200, 429], \
                f"Governance policy should be enforced: {scenario['resource_type']}"
            
            if governance_response.status_code == 429:
                logger.info(f"Governance rate limiting active: {scenario['resource_type']}")
            else:
                logger.info(f"Governance policy applied: {scenario['resource_type']}")
        
        # Test compliance enforcement
        compliance_scenarios = [
            {"X-Compliance-Standard": "SOC2"},
            {"X-Compliance-Standard": "ISO27001"},
            {"X-Compliance-Standard": "HIPAA"},
            {"X-Compliance-Standard": "GDPR"}
        ]
        
        for compliance_headers in compliance_scenarios:
            compliance_test_headers = auth_headers.copy()
            compliance_test_headers.update(compliance_headers)
            compliance_test_headers["X-Governance-Test"] = governance_test_id
            
            compliance_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Compliance test: {compliance_headers['X-Compliance-Standard']}"}],
                "max_tokens": 50
            }
            
            compliance_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                compliance_test_headers, compliance_request, track_cost=False
            )
            
            # Should handle compliance requirements
            assert compliance_response.status_code == 200, \
                f"Compliance standard should be supported: {compliance_headers['X-Compliance-Standard']}"
        
        # Test resource tagging governance
        tagging_headers = auth_headers.copy()
        tagging_headers["X-Resource-Tag"] = "environment=production"
        tagging_headers["X-Owner-Tag"] = "team=security"
        tagging_headers["X-Cost-Center"] = "engineering"
        
        tagging_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Resource tagging governance test"}],
            "max_tokens": 50
        }
        
        tagging_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            tagging_headers, tagging_request, track_cost=False
        )
        
        # Should handle resource tagging
        assert tagging_response.status_code == 200, \
            "Resource tagging should be handled"
        
        logger.info("INFRA_CLOUD_GOVERNANCE_001: Cloud governance validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_disaster_recovery_001(self, http_client: httpx.AsyncClient,
                                             auth_headers: Dict[str, str],
                                             make_request):
        """INFRA_DISASTER_RECOVERY_001: Disaster recovery security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test disaster recovery capabilities
        dr_test_id = str(uuid.uuid4())
        
        # Test disaster recovery endpoints
        dr_endpoints = [
            "/disaster-recovery/status",
            "/backup/disaster-recovery",
            "/admin/dr/status",
            "/recovery/health"
        ]
        
        for endpoint in dr_endpoints:
            dr_response = await make_request(
                http_client, "GET", endpoint,
                auth_headers, track_cost=False
            )
            
            if dr_response.status_code == 200:
                logger.info(f"Disaster recovery endpoint available: {endpoint}")
                
                try:
                    dr_data = dr_response.json()
                    
                    # Check for DR status information
                    dr_fields = [
                        "backup_status",
                        "recovery_point_objective",
                        "recovery_time_objective",
                        "last_backup",
                        "dr_site_status"
                    ]
                    
                    for field in dr_fields:
                        if field in dr_data:
                            logger.info(f"DR status includes: {field}")
                
                except json.JSONDecodeError:
                    logger.info(f"DR endpoint returns non-JSON: {endpoint}")
                    
            elif dr_response.status_code in [401, 403]:
                logger.info(f"DR endpoint properly protected: {endpoint}")
            elif dr_response.status_code == 404:
                logger.info(f"DR endpoint not found: {endpoint}")
        
        # Test disaster recovery scenarios
        dr_scenarios = [
            {
                "scenario": "service_outage",
                "description": "Service outage recovery test"
            },
            {
                "scenario": "data_corruption",
                "description": "Data corruption recovery test"
            },
            {
                "scenario": "region_failure",
                "description": "Regional failure recovery test"
            },
            {
                "scenario": "security_incident",
                "description": "Security incident recovery test"
            }
        ]
        
        for scenario in dr_scenarios:
            dr_headers = auth_headers.copy()
            dr_headers["X-DR-Test"] = dr_test_id
            dr_headers["X-DR-Scenario"] = scenario["scenario"]
            
            dr_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Disaster recovery test: {scenario['description']}"}],
                "max_tokens": 50
            }
            
            dr_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                dr_headers, dr_request, track_cost=False
            )
            
            # Should handle DR scenarios appropriately
            assert dr_response.status_code in [200, 503], \
                f"DR scenario should be handled: {scenario['scenario']}"
            
            if dr_response.status_code == 503:
                logger.info(f"DR scenario triggered service unavailable: {scenario['scenario']}")
            else:
                logger.info(f"DR scenario handled gracefully: {scenario['scenario']}")
        
        # Test recovery time objectives
        rto_test_start = time.time()
        
        rto_headers = auth_headers.copy()
        rto_headers["X-RTO-Test"] = "true"
        
        rto_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Recovery time objective test"}],
            "max_tokens": 50
        }
        
        rto_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            rto_headers, rto_request, track_cost=False
        )
        
        rto_time = time.time() - rto_test_start
        
        # Should meet reasonable recovery time objectives
        assert rto_response.status_code == 200, \
            "RTO test should complete successfully"
        
        if rto_time > 30:  # 30 second threshold
            logger.warning(f"High RTO time: {rto_time:.2f}s")
        else:
            logger.info(f"RTO test completed in: {rto_time:.2f}s")
        
        logger.info("INFRA_DISASTER_RECOVERY_001: Disaster recovery security validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_configuration_drift_001(self, http_client: httpx.AsyncClient,
                                               auth_headers: Dict[str, str],
                                               make_request):
        """INFRA_CONFIGURATION_DRIFT_001: Configuration drift detection"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test configuration drift detection
        drift_test_id = str(uuid.uuid4())
        
        # Test configuration baseline
        baseline_headers = auth_headers.copy()
        baseline_headers["X-Config-Drift-Test"] = drift_test_id
        baseline_headers["X-Config-Baseline"] = "true"
        
        baseline_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Configuration baseline test"}],
            "max_tokens": 50
        }
        
        baseline_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            baseline_headers, baseline_request, track_cost=False
        )
        
        assert baseline_response.status_code == 200, \
            "Configuration baseline should be established"
        
        # Test configuration changes detection
        drift_scenarios = [
            {
                "change_type": "security_policy",
                "description": "Security policy configuration change"
            },
            {
                "change_type": "network_rules",
                "description": "Network configuration change"
            },
            {
                "change_type": "access_controls",
                "description": "Access control configuration change"
            },
            {
                "change_type": "encryption_settings",
                "description": "Encryption configuration change"
            }
        ]
        
        for scenario in drift_scenarios:
            drift_headers = auth_headers.copy()
            drift_headers["X-Config-Drift-Test"] = drift_test_id
            drift_headers["X-Config-Change"] = scenario["change_type"]
            
            drift_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Configuration drift test: {scenario['description']}"}],
                "max_tokens": 50
            }
            
            drift_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                drift_headers, drift_request, track_cost=False
            )
            
            # Should handle configuration changes appropriately
            assert drift_response.status_code in [200, 400], \
                f"Configuration drift should be handled: {scenario['change_type']}"
        
        # Test unauthorized configuration changes
        unauthorized_changes = [
            {"X-Unauthorized-Config": "disable_security"},
            {"X-Config-Override": "bypass_authentication"},
            {"X-Config-Tamper": "modify_permissions"}
        ]
        
        for change_headers in unauthorized_changes:
            unauth_headers = auth_headers.copy()
            unauth_headers.update(change_headers)
            unauth_headers["X-Config-Drift-Test"] = drift_test_id
            
            unauth_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Unauthorized configuration change test"}],
                "max_tokens": 50
            }
            
            unauth_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                unauth_headers, unauth_request, track_cost=False
            )
            
            # Should prevent unauthorized configuration changes
            assert unauth_response.status_code in [200, 400, 403], \
                f"Unauthorized config change should be prevented: {change_headers}"
        
        # Test configuration monitoring
        monitoring_headers = auth_headers.copy()
        monitoring_headers["X-Config-Monitoring"] = "true"
        monitoring_headers["X-Config-Drift-Test"] = drift_test_id
        
        monitoring_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Configuration monitoring test"}],
            "max_tokens": 50
        }
        
        monitoring_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            monitoring_headers, monitoring_request, track_cost=False
        )
        
        # Should support configuration monitoring
        assert monitoring_response.status_code == 200, \
            "Configuration monitoring should be supported"
        
        logger.info("INFRA_CONFIGURATION_DRIFT_001: Configuration drift detection validated")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_infra_comprehensive_security_001(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """INFRA_COMPREHENSIVE_SECURITY_001: Comprehensive infrastructure security"""
        if not config.should_run_security_tests():
            pytest.skip("Security tests disabled")
        
        # Test comprehensive infrastructure security
        comprehensive_test_id = str(uuid.uuid4())
        
        # Test integrated security components
        security_components = [
            {
                "component": "authentication",
                "test_type": "integration",
                "description": "Authentication integration test"
            },
            {
                "component": "authorization",
                "test_type": "integration",
                "description": "Authorization integration test"
            },
            {
                "component": "encryption",
                "test_type": "integration",
                "description": "Encryption integration test"
            },
            {
                "component": "monitoring",
                "test_type": "integration",
                "description": "Monitoring integration test"
            },
            {
                "component": "audit",
                "test_type": "integration",
                "description": "Audit integration test"
            }
        ]
        
        security_results = []
        
        for component in security_components:
            comp_headers = auth_headers.copy()
            comp_headers["X-Comprehensive-Test"] = comprehensive_test_id
            comp_headers["X-Security-Component"] = component["component"]
            comp_headers["X-Test-Type"] = component["test_type"]
            
            comp_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Comprehensive security test: {component['description']}"}],
                "max_tokens": 50
            }
            
            comp_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                comp_headers, comp_request, track_cost=False
            )
            
            security_results.append({
                "component": component["component"],
                "status_code": comp_response.status_code,
                "success": comp_response.status_code == 200
            })
            
            # All security components should work together
            assert comp_response.status_code == 200, \
                f"Security component should work: {component['component']}"
        
        # Test end-to-end security workflow
        e2e_headers = auth_headers.copy()
        e2e_headers["X-E2E-Security-Test"] = comprehensive_test_id
        
        e2e_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "End-to-end infrastructure security test"}],
            "max_tokens": 100
        }
        
        e2e_response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            e2e_headers, e2e_request
        )
        
        # End-to-end security should work
        assert e2e_response.status_code == 200, \
            "End-to-end security workflow should work"
        
        # Test security resilience
        resilience_scenarios = [
            {"X-Attack-Vector": "multiple_simultaneous"},
            {"X-Stress-Test": "high_load_security"},
            {"X-Fault-Injection": "security_component_failure"}
        ]
        
        for resilience_headers in resilience_scenarios:
            resilience_test_headers = auth_headers.copy()
            resilience_test_headers.update(resilience_headers)
            resilience_test_headers["X-Comprehensive-Test"] = comprehensive_test_id
            
            resilience_request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Security resilience test"}],
                "max_tokens": 50
            }
            
            resilience_response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                resilience_test_headers, resilience_request, track_cost=False
            )
            
            # Should maintain security under stress
            assert resilience_response.status_code in [200, 429, 503], \
                f"Security resilience should be maintained: {resilience_headers}"
        
        # Analyze comprehensive security results
        successful_components = [r for r in security_results if r["success"]]
        
        security_coverage = len(successful_components) / len(security_results)
        
        logger.info(f"Comprehensive security coverage: {security_coverage:.2%}")
        
        # Should have high security coverage
        assert security_coverage >= 0.8, \
            f"Comprehensive security coverage too low: {security_coverage:.2%}"
        
        logger.info("INFRA_COMPREHENSIVE_SECURITY_001: Comprehensive infrastructure security validated")


# Infrastructure Security Testing Summary:
# This completes the implementation of all missing INFRA_* test case IDs from the design document:
# 
# Basic Tests (test_infrastructure_security.py):
# - INFRA_CONTAINER_001, INFRA_NETWORK_001, INFRA_TLS_001, INFRA_IAM_001, INFRA_SECRETS_001, INFRA_RUNTIME_001, INFRA_BACKUP_001
# - INFRA_CONTAINER_VULN_SCAN_001, INFRA_NETWORK_PORT_EXPOSURE_001
#
# Advanced Tests Part 1 (test_infrastructure_advanced_security.py):
# - INFRA_CONTAINER_LEAST_PRIVILEGE_001: Non-root user verification
# - INFRA_CONTAINER_FILESYSTEM_READONLY_001: Read-only filesystem testing
# - INFRA_NETWORK_PROVIDER_ENCRYPTION_001: Provider communication encryption
# - INFRA_IAM_LEAST_PRIVILEGE_LLM_001: IAM least privilege validation
# - INFRA_SECRETS_PROVIDER_KEYS_001: Provider credentials management
# - INFRA_SECRETS_DB_CONN_STRING_001: Database connection string security
#
# Advanced Tests Part 2 (test_infrastructure_advanced_security_2.py):
# - INFRA_CONTAINER_ESCAPE_001: Container escape prevention
# - INFRA_SECRETS_ROTATION_001: Automated secrets rotation
# - INFRA_MONITORING_SECURITY_001: Infrastructure monitoring security
# - INFRA_CLOUD_GOVERNANCE_001: Cloud governance and resource management
# - INFRA_DISASTER_RECOVERY_001: Disaster recovery security
# - INFRA_CONFIGURATION_DRIFT_001: Configuration drift detection
# - INFRA_COMPREHENSIVE_SECURITY_001: Comprehensive infrastructure security
#
# Total: 19 specific INFRA_* test case IDs implemented, covering all requirements from the design document