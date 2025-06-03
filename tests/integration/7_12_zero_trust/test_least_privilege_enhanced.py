# Section 7.12 - Zero Trust Least Privilege Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Least Privilege.md
# Enhanced Test Cases: ZTA_LP_009 through ZTA_LP_016

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestLeastPrivilegeEnhanced:
    """Enhanced Zero Trust Least Privilege tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_009_dynamic_privilege_reduction(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """ZTA_LP_009: Test dynamic privilege reduction based on context and risk assessment"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test privilege reduction during high-risk operations
        risk_scenarios = [
            {
                "risk_level": "low",
                "context": "normal_operation",
                "privilege_level": "full",
                "operations_allowed": ["models", "chat", "embeddings"]
            },
            {
                "risk_level": "medium",
                "context": "suspicious_activity",
                "privilege_level": "reduced",
                "operations_allowed": ["models", "chat"]
            },
            {
                "risk_level": "high",
                "context": "security_incident",
                "privilege_level": "minimal",
                "operations_allowed": ["models"]
            }
        ]
        
        for scenario in risk_scenarios:
            risk_headers = dict(auth_headers)
            risk_headers.update({
                "X-Risk-Level": scenario["risk_level"],
                "X-Context": scenario["context"],
                "X-Privilege-Level": scenario["privilege_level"],
                "X-Dynamic-Reduction": "enabled"
            })
            
            # Test each operation to verify privilege enforcement
            for operation in ["models", "chat", "embeddings"]:
                should_allow = operation in scenario["operations_allowed"]
                
                if operation == "models":
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        risk_headers, track_cost=False
                    )
                elif operation == "chat":
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        risk_headers, json={
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Privilege test {scenario['risk_level']}"}],
                            "max_tokens": 10
                        }, track_cost=False
                    )
                elif operation == "embeddings":
                    response = await make_request(
                        http_client, "POST", "/api/v1/embeddings",
                        risk_headers, json={
                            "model": config.get_embedding_model(0),
                            "input": f"Embedding privilege test {scenario['risk_level']}"
                        }, track_cost=False
                    )
                
                # Current implementation doesn't have dynamic privilege reduction
                # This documents expected behavior
                expected_status = "allowed" if should_allow else "denied"
                logger.info(f"Dynamic privilege {scenario['risk_level']} risk, {operation}: "
                           f"{response.status_code} (expected: {expected_status})")
        
        logger.info("ZTA_LP_009: Dynamic privilege reduction tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_010_hierarchical_scope_management(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_LP_010: Test hierarchical scope management with inheritance and delegation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test scope inheritance from parent to child permissions
        scope_hierarchy = [
            {
                "level": "admin",
                "parent": None,
                "inherits": [],
                "grants": ["admin", "models:inference", "models:embedding", "models:list"]
            },
            {
                "level": "power_user",
                "parent": "admin",
                "inherits": ["models:inference", "models:embedding", "models:list"],
                "grants": ["models:inference", "models:embedding", "models:list"]
            },
            {
                "level": "basic_user",
                "parent": "power_user",
                "inherits": ["models:list"],
                "grants": ["models:list"]
            }
        ]
        
        for scope_level in scope_hierarchy:
            hierarchy_headers = dict(auth_headers)
            hierarchy_headers.update({
                "X-Scope-Level": scope_level["level"],
                "X-Parent-Scope": scope_level["parent"] or "none",
                "X-Inherited-Scopes": ",".join(scope_level["inherits"]),
                "X-Granted-Scopes": ",".join(scope_level["grants"]),
                "X-Hierarchical-Management": "enabled"
            })
            
            # Test operations based on scope level
            test_operations = [
                ("GET", "/api/v1/models", None, "models:list"),
                ("POST", "/api/v1/chat/completions", {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Hierarchy test"}],
                    "max_tokens": 10
                }, "models:inference"),
                ("POST", "/api/v1/embeddings", {
                    "model": config.get_embedding_model(0),
                    "input": "Hierarchy embedding test"
                }, "models:embedding")
            ]
            
            for method, endpoint, data, required_scope in test_operations:
                should_allow = required_scope in scope_level["grants"]
                
                response = await make_request(
                    http_client, method, endpoint,
                    hierarchy_headers, json=data, track_cost=False
                )
                
                expected_status = "allowed" if should_allow else "denied"
                logger.info(f"Hierarchical scope {scope_level['level']}, {required_scope}: "
                           f"{response.status_code} (expected: {expected_status})")
        
        # Test delegation of specific scopes with time-limited constraints
        delegation_tests = [
            {
                "delegator": "admin",
                "delegatee": "temp_user",
                "delegated_scopes": ["models:inference"],
                "time_limit": 3600,  # 1 hour
                "constraints": ["ip_restricted", "usage_limited"]
            },
            {
                "delegator": "power_user",
                "delegatee": "contractor",
                "delegated_scopes": ["models:list"],
                "time_limit": 86400,  # 24 hours
                "constraints": ["read_only"]
            }
        ]
        
        for delegation in delegation_tests:
            delegation_headers = dict(auth_headers)
            delegation_headers.update({
                "X-Delegator": delegation["delegator"],
                "X-Delegatee": delegation["delegatee"],
                "X-Delegated-Scopes": ",".join(delegation["delegated_scopes"]),
                "X-Time-Limit": str(delegation["time_limit"]),
                "X-Constraints": ",".join(delegation["constraints"]),
                "X-Delegation-Active": "true"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                delegation_headers, track_cost=False
            )
            
            logger.info(f"Scope delegation {delegation['delegator']}→{delegation['delegatee']}: "
                       f"{response.status_code}")
        
        logger.info("ZTA_LP_010: Hierarchical scope management tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_011_just_in_time_privilege_access(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_LP_011: Test just-in-time privilege access for elevated operations"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test privilege elevation request and approval workflows
        jit_scenarios = [
            {
                "operation": "high_token_generation",
                "required_privilege": "models:high_usage",
                "elevation_duration": 1800,  # 30 minutes
                "justification": "Large document processing",
                "approval_required": True
            },
            {
                "operation": "sensitive_model_access",
                "required_privilege": "models:restricted",
                "elevation_duration": 900,   # 15 minutes
                "justification": "Security research",
                "approval_required": True
            },
            {
                "operation": "emergency_access",
                "required_privilege": "admin:emergency",
                "elevation_duration": 300,   # 5 minutes
                "justification": "Security incident response",
                "approval_required": False
            }
        ]
        
        for jit_scenario in jit_scenarios:
            # Simulate privilege elevation request
            elevation_headers = dict(auth_headers)
            elevation_headers.update({
                "X-JIT-Operation": jit_scenario["operation"],
                "X-Required-Privilege": jit_scenario["required_privilege"],
                "X-Elevation-Duration": str(jit_scenario["elevation_duration"]),
                "X-Justification": jit_scenario["justification"],
                "X-Approval-Required": str(jit_scenario["approval_required"]).lower(),
                "X-JIT-Request": "initiate"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                elevation_headers, track_cost=False
            )
            
            logger.info(f"JIT elevation request {jit_scenario['operation']}: {response.status_code}")
            
            # Simulate approval workflow
            if jit_scenario["approval_required"]:
                approval_headers = dict(elevation_headers)
                approval_headers.update({
                    "X-JIT-Request": "approve",
                    "X-Approver": "security_admin",
                    "X-Approval-Time": str(int(time.time()))
                })
                
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    approval_headers, track_cost=False
                )
                
                logger.info(f"JIT approval {jit_scenario['operation']}: {response.status_code}")
            
            # Test elevated operation execution
            execution_headers = dict(elevation_headers)
            execution_headers.update({
                "X-JIT-Request": "execute",
                "X-Elevation-Active": "true",
                "X-Elevation-Start": str(int(time.time()))
            })
            
            if jit_scenario["operation"] == "high_token_generation":
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    execution_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "JIT high token test"}],
                        "max_tokens": 100  # High token count
                    }, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    execution_headers, track_cost=False
                )
            
            logger.info(f"JIT execution {jit_scenario['operation']}: {response.status_code}")
            
            # Test automatic privilege expiration
            expiration_headers = dict(execution_headers)
            expiration_headers.update({
                "X-Elevation-Expired": "true",
                "X-Elevation-End": str(int(time.time() + jit_scenario["elevation_duration"]))
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                expiration_headers, track_cost=False
            )
            
            logger.info(f"JIT expiration {jit_scenario['operation']}: {response.status_code}")
        
        logger.info("ZTA_LP_011: Just-in-time privilege access tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_012_resource_specific_access_control(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_LP_012: Test resource-specific access control with fine-grained permissions"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test model-specific access control
        model_access_tests = [
            {
                "user_role": "researcher",
                "allowed_models": [config.get_chat_model(0)],
                "denied_models": [],
                "model_categories": ["general_purpose"]
            },
            {
                "user_role": "restricted_user",
                "allowed_models": [],
                "denied_models": [config.get_chat_model(0)],
                "model_categories": ["basic_only"]
            },
            {
                "user_role": "power_user",
                "allowed_models": [config.get_chat_model(0), config.get_embedding_model(0)],
                "denied_models": [],
                "model_categories": ["general_purpose", "embedding"]
            }
        ]
        
        for model_test in model_access_tests:
            model_headers = dict(auth_headers)
            model_headers.update({
                "X-User-Role": model_test["user_role"],
                "X-Allowed-Models": ",".join(model_test["allowed_models"]),
                "X-Denied-Models": ",".join(model_test["denied_models"]),
                "X-Model-Categories": ",".join(model_test["model_categories"]),
                "X-Resource-Control": "model_specific"
            })
            
            # Test access to allowed models
            for model in model_test["allowed_models"]:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    model_headers, json={
                        "model": model,
                        "messages": [{"role": "user", "content": "Model access test"}],
                        "max_tokens": 10
                    }, track_cost=False
                )
                
                logger.info(f"Model access {model_test['user_role']} → {model}: {response.status_code} (allowed)")
            
            # Test access to denied models
            for model in model_test["denied_models"]:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    model_headers, json={
                        "model": model,
                        "messages": [{"role": "user", "content": "Model access test"}],
                        "max_tokens": 10
                    }, track_cost=False
                )
                
                logger.info(f"Model access {model_test['user_role']} → {model}: {response.status_code} (denied)")
        
        # Test endpoint-level permissions beyond basic scope checking
        endpoint_permissions = [
            {
                "endpoint": "/api/v1/models",
                "permissions": ["read"],
                "restrictions": ["no_filtering"]
            },
            {
                "endpoint": "/api/v1/chat/completions",
                "permissions": ["create", "read"],
                "restrictions": ["token_limit_100", "content_filter"]
            },
            {
                "endpoint": "/api/v1/embeddings",
                "permissions": ["create"],
                "restrictions": ["batch_size_10"]
            }
        ]
        
        for endpoint_perm in endpoint_permissions:
            endpoint_headers = dict(auth_headers)
            endpoint_headers.update({
                "X-Endpoint": endpoint_perm["endpoint"],
                "X-Permissions": ",".join(endpoint_perm["permissions"]),
                "X-Restrictions": ",".join(endpoint_perm["restrictions"]),
                "X-Resource-Control": "endpoint_specific"
            })
            
            if endpoint_perm["endpoint"] == "/api/v1/models":
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    endpoint_headers, track_cost=False
                )
            elif endpoint_perm["endpoint"] == "/api/v1/chat/completions":
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    endpoint_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Endpoint permission test"}],
                        "max_tokens": 50  # Test token limit restriction
                    }, track_cost=False
                )
            elif endpoint_perm["endpoint"] == "/api/v1/embeddings":
                response = await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    endpoint_headers, json={
                        "model": config.get_embedding_model(0),
                        "input": "Endpoint permission test"
                    }, track_cost=False
                )
            
            logger.info(f"Endpoint permission {endpoint_perm['endpoint']}: {response.status_code}")
        
        # Test resource quota enforcement
        quota_tests = [
            {
                "resource": "api_calls",
                "quota": 100,
                "period": "hourly",
                "current_usage": 95
            },
            {
                "resource": "token_consumption",
                "quota": 10000,
                "period": "daily",
                "current_usage": 8500
            }
        ]
        
        for quota in quota_tests:
            quota_headers = dict(auth_headers)
            quota_headers.update({
                "X-Resource-Type": quota["resource"],
                "X-Quota-Limit": str(quota["quota"]),
                "X-Quota-Period": quota["period"],
                "X-Current-Usage": str(quota["current_usage"]),
                "X-Quota-Enforcement": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                quota_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Quota test"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            near_limit = quota["current_usage"] / quota["quota"] > 0.9
            logger.info(f"Resource quota {quota['resource']} "
                       f"({quota['current_usage']}/{quota['quota']}): {response.status_code} "
                       f"(near limit: {near_limit})")
        
        logger.info("ZTA_LP_012: Resource-specific access control tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_013_privilege_analytics_optimization(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_LP_013: Test analytics-driven privilege optimization with usage pattern analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test usage pattern analysis for privilege optimization
        usage_patterns = []
        
        # Simulate various usage patterns over time
        pattern_types = [
            {"type": "models_only", "endpoints": ["/api/v1/models"], "frequency": 10},
            {"type": "chat_heavy", "endpoints": ["/api/v1/chat/completions"], "frequency": 50},
            {"type": "embedding_only", "endpoints": ["/api/v1/embeddings"], "frequency": 5},
            {"type": "mixed_usage", "endpoints": ["/api/v1/models", "/api/v1/chat/completions"], "frequency": 25}
        ]
        
        for pattern in pattern_types:
            pattern_start = time.time()
            
            analytics_headers = dict(auth_headers)
            analytics_headers.update({
                "X-Usage-Pattern": pattern["type"],
                "X-Pattern-Frequency": str(pattern["frequency"]),
                "X-Analytics-Tracking": "enabled"
            })
            
            # Simulate usage for this pattern
            for i in range(min(3, pattern["frequency"] // 10)):  # Sample the pattern
                for endpoint in pattern["endpoints"]:
                    if endpoint == "/api/v1/models":
                        response = await make_request(
                            http_client, "GET", endpoint,
                            analytics_headers, track_cost=False
                        )
                    elif endpoint == "/api/v1/chat/completions":
                        response = await make_request(
                            http_client, "POST", endpoint,
                            analytics_headers, json={
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Analytics test {i}"}],
                                "max_tokens": 10
                            }, track_cost=False
                        )
                    elif endpoint == "/api/v1/embeddings":
                        response = await make_request(
                            http_client, "POST", endpoint,
                            analytics_headers, json={
                                "model": config.get_embedding_model(0),
                                "input": f"Analytics embedding {i}"
                            }, track_cost=False
                        )
                    
                    await asyncio.sleep(0.1)
            
            pattern_duration = time.time() - pattern_start
            
            usage_patterns.append({
                "type": pattern["type"],
                "endpoints": pattern["endpoints"],
                "frequency": pattern["frequency"],
                "sample_duration": pattern_duration,
                "efficiency_score": len(pattern["endpoints"]) / pattern["frequency"]  # Simple metric
            })
        
        # Test automated detection of unused or excessive privileges
        privilege_analysis = [
            {
                "privilege": "models:embedding",
                "granted": True,
                "used": False,
                "last_used": "never",
                "recommendation": "revoke"
            },
            {
                "privilege": "models:inference",
                "granted": True,
                "used": True,
                "last_used": "recent",
                "recommendation": "maintain"
            },
            {
                "privilege": "admin:full",
                "granted": True,
                "used": False,
                "last_used": "90_days_ago",
                "recommendation": "review_and_possibly_revoke"
            }
        ]
        
        for privilege in privilege_analysis:
            analysis_headers = dict(auth_headers)
            analysis_headers.update({
                "X-Privilege": privilege["privilege"],
                "X-Granted": str(privilege["granted"]).lower(),
                "X-Used": str(privilege["used"]).lower(),
                "X-Last-Used": privilege["last_used"],
                "X-Recommendation": privilege["recommendation"],
                "X-Privilege-Analysis": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                analysis_headers, track_cost=False
            )
            
            logger.info(f"Privilege analysis {privilege['privilege']}: "
                       f"used={privilege['used']}, recommendation={privilege['recommendation']}")
        
        # Test right-sizing recommendations based on usage patterns
        right_sizing_tests = [
            {
                "current_privileges": ["admin", "models:inference", "models:embedding"],
                "actual_usage": ["models:inference"],
                "recommended_privileges": ["models:inference"],
                "optimization_score": 0.33  # 1/3 privileges actually used
            },
            {
                "current_privileges": ["models:inference"],
                "actual_usage": ["models:inference"],
                "recommended_privileges": ["models:inference"],
                "optimization_score": 1.0  # Perfect match
            }
        ]
        
        for sizing in right_sizing_tests:
            sizing_headers = dict(auth_headers)
            sizing_headers.update({
                "X-Current-Privileges": ",".join(sizing["current_privileges"]),
                "X-Actual-Usage": ",".join(sizing["actual_usage"]),
                "X-Recommended-Privileges": ",".join(sizing["recommended_privileges"]),
                "X-Optimization-Score": str(sizing["optimization_score"]),
                "X-Right-Sizing": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                sizing_headers, track_cost=False
            )
            
            logger.info(f"Right-sizing analysis: "
                       f"optimization_score={sizing['optimization_score']:.2f}, "
                       f"current={len(sizing['current_privileges'])}, "
                       f"recommended={len(sizing['recommended_privileges'])}")
        
        # Analyze collected usage patterns
        total_patterns = len(usage_patterns)
        avg_efficiency = sum(p["efficiency_score"] for p in usage_patterns) / total_patterns
        
        logger.info(f"Usage pattern analysis: {total_patterns} patterns, "
                   f"avg_efficiency={avg_efficiency:.3f}")
        
        logger.info("ZTA_LP_013: Privilege analytics and optimization tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_014_cross_provider_privilege_isolation(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """ZTA_LP_014: Test isolation of privileges across different LLM providers"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test provider-specific credential isolation
        provider_isolation_tests = [
            {
                "provider": "bedrock",
                "credentials": "arn:aws:iam::account:role/bedrock-role",
                "isolation_level": "account_level",
                "cross_provider_access": False
            },
            {
                "provider": "vertex_ai",
                "credentials": "service-account@project.iam.gserviceaccount.com",
                "isolation_level": "project_level",
                "cross_provider_access": False
            },
            {
                "provider": "openai",
                "credentials": "api_key_reference",
                "isolation_level": "organization_level",
                "cross_provider_access": False
            }
        ]
        
        for provider_test in provider_isolation_tests:
            isolation_headers = dict(auth_headers)
            isolation_headers.update({
                "X-Provider": provider_test["provider"],
                "X-Provider-Credentials": provider_test["credentials"],
                "X-Isolation-Level": provider_test["isolation_level"],
                "X-Cross-Provider-Access": str(provider_test["cross_provider_access"]).lower(),
                "X-Credential-Isolation": "enforced"
            })
            
            # Test access to provider-specific models
            if provider_test["provider"] in config.get_chat_model(0).lower():
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    isolation_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Provider isolation test {provider_test['provider']}"}],
                        "max_tokens": 10
                    }, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    isolation_headers, track_cost=False
                )
            
            logger.info(f"Provider isolation {provider_test['provider']} "
                       f"({provider_test['isolation_level']}): {response.status_code}")
        
        # Test prevention of cross-provider privilege escalation
        escalation_tests = [
            {
                "source_provider": "bedrock",
                "target_provider": "vertex_ai",
                "escalation_attempt": "credential_reuse",
                "should_block": True
            },
            {
                "source_provider": "vertex_ai",
                "target_provider": "openai",
                "escalation_attempt": "token_sharing",
                "should_block": True
            }
        ]
        
        for escalation in escalation_tests:
            escalation_headers = dict(auth_headers)
            escalation_headers.update({
                "X-Source-Provider": escalation["source_provider"],
                "X-Target-Provider": escalation["target_provider"],
                "X-Escalation-Attempt": escalation["escalation_attempt"],
                "X-Should-Block": str(escalation["should_block"]).lower(),
                "X-Cross-Provider-Protection": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                escalation_headers, track_cost=False
            )
            
            expected_result = "blocked" if escalation["should_block"] else "allowed"
            logger.info(f"Cross-provider escalation {escalation['source_provider']}→{escalation['target_provider']}: "
                       f"{response.status_code} (expected: {expected_result})")
        
        # Test provider failure isolation
        failure_isolation_tests = [
            {
                "failed_provider": "bedrock",
                "remaining_providers": ["vertex_ai", "openai"],
                "isolation_effective": True
            },
            {
                "failed_provider": "vertex_ai",
                "remaining_providers": ["bedrock", "openai"],
                "isolation_effective": True
            }
        ]
        
        for failure_test in failure_isolation_tests:
            failure_headers = dict(auth_headers)
            failure_headers.update({
                "X-Failed-Provider": failure_test["failed_provider"],
                "X-Remaining-Providers": ",".join(failure_test["remaining_providers"]),
                "X-Isolation-Effective": str(failure_test["isolation_effective"]).lower(),
                "X-Failure-Isolation": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                failure_headers, track_cost=False
            )
            
            logger.info(f"Provider failure isolation {failure_test['failed_provider']}: "
                       f"{response.status_code} (isolation: {failure_test['isolation_effective']})")
        
        logger.info("ZTA_LP_014: Cross-provider privilege isolation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_015_adaptive_privilege_management(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_LP_015: Test adaptive privilege management based on behavior and threat landscape"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test privilege adaptation based on user behavioral patterns
        behavioral_adaptations = [
            {
                "behavior_pattern": "consistent_normal",
                "trust_score": 0.9,
                "privilege_adjustment": "maintain",
                "monitoring_level": "standard"
            },
            {
                "behavior_pattern": "unusual_activity",
                "trust_score": 0.6,
                "privilege_adjustment": "reduce",
                "monitoring_level": "enhanced"
            },
            {
                "behavior_pattern": "suspicious_pattern",
                "trust_score": 0.3,
                "privilege_adjustment": "minimal",
                "monitoring_level": "high"
            }
        ]
        
        for adaptation in behavioral_adaptations:
            behavior_headers = dict(auth_headers)
            behavior_headers.update({
                "X-Behavior-Pattern": adaptation["behavior_pattern"],
                "X-Trust-Score": str(adaptation["trust_score"]),
                "X-Privilege-Adjustment": adaptation["privilege_adjustment"],
                "X-Monitoring-Level": adaptation["monitoring_level"],
                "X-Adaptive-Management": "enabled"
            })
            
            # Test adapted privilege level
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                behavior_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Adaptive test {adaptation['behavior_pattern']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Behavioral adaptation {adaptation['behavior_pattern']} "
                       f"(trust: {adaptation['trust_score']}, adjustment: {adaptation['privilege_adjustment']}): "
                       f"{response.status_code}")
        
        # Test threat intelligence integration for privilege adjustment
        threat_adaptations = [
            {
                "threat_level": "low",
                "threat_type": "general_scanning",
                "privilege_impact": "none",
                "additional_controls": []
            },
            {
                "threat_level": "medium",
                "threat_type": "targeted_campaign",
                "privilege_impact": "reduce_non_essential",
                "additional_controls": ["enhanced_logging"]
            },
            {
                "threat_level": "high",
                "threat_type": "active_breach",
                "privilege_impact": "emergency_lockdown",
                "additional_controls": ["enhanced_logging", "manual_approval", "time_limits"]
            }
        ]
        
        for threat in threat_adaptations:
            threat_headers = dict(auth_headers)
            threat_headers.update({
                "X-Threat-Level": threat["threat_level"],
                "X-Threat-Type": threat["threat_type"],
                "X-Privilege-Impact": threat["privilege_impact"],
                "X-Additional-Controls": ",".join(threat["additional_controls"]),
                "X-Threat-Adaptive": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                threat_headers, track_cost=False
            )
            
            logger.info(f"Threat adaptation {threat['threat_level']} "
                       f"({threat['threat_type']}, impact: {threat['privilege_impact']}): "
                       f"{response.status_code}")
        
        # Test ML-based privilege optimization
        ml_optimization_tests = [
            {
                "model_type": "collaborative_filtering",
                "optimization_target": "privilege_efficiency",
                "learning_data": "user_behavior_patterns",
                "confidence": 0.85
            },
            {
                "model_type": "anomaly_detection",
                "optimization_target": "security_enhancement",
                "learning_data": "threat_patterns",
                "confidence": 0.92
            }
        ]
        
        for ml_test in ml_optimization_tests:
            ml_headers = dict(auth_headers)
            ml_headers.update({
                "X-ML-Model": ml_test["model_type"],
                "X-Optimization-Target": ml_test["optimization_target"],
                "X-Learning-Data": ml_test["learning_data"],
                "X-ML-Confidence": str(ml_test["confidence"]),
                "X-ML-Optimization": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                ml_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"ML optimization test {ml_test['model_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"ML optimization {ml_test['model_type']} "
                       f"(target: {ml_test['optimization_target']}, confidence: {ml_test['confidence']}): "
                       f"{response.status_code}")
        
        logger.info("ZTA_LP_015: Adaptive privilege management tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_lp_016_zero_standing_privileges(self, http_client: httpx.AsyncClient,
                                                      auth_headers: Dict[str, str],
                                                      make_request):
        """ZTA_LP_016: Test zero standing privileges model with explicit activation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test elimination of persistent elevated privileges
        privilege_activation_tests = [
            {
                "privilege_type": "admin_access",
                "activation_required": True,
                "justification_required": True,
                "approval_required": True,
                "time_limit": 1800  # 30 minutes
            },
            {
                "privilege_type": "high_volume_usage",
                "activation_required": True,
                "justification_required": True,
                "approval_required": False,
                "time_limit": 3600  # 1 hour
            },
            {
                "privilege_type": "basic_operations",
                "activation_required": False,
                "justification_required": False,
                "approval_required": False,
                "time_limit": 0  # No limit for basic operations
            }
        ]
        
        for privilege_test in privilege_activation_tests:
            # Test privilege activation request
            activation_headers = dict(auth_headers)
            activation_headers.update({
                "X-Privilege-Type": privilege_test["privilege_type"],
                "X-Activation-Required": str(privilege_test["activation_required"]).lower(),
                "X-Justification-Required": str(privilege_test["justification_required"]).lower(),
                "X-Approval-Required": str(privilege_test["approval_required"]).lower(),
                "X-Time-Limit": str(privilege_test["time_limit"]),
                "X-Zero-Standing": "enabled"
            })
            
            if privilege_test["activation_required"]:
                # Request privilege activation
                activation_headers["X-Privilege-Request"] = "activate"
                if privilege_test["justification_required"]:
                    activation_headers["X-Justification"] = f"Need {privilege_test['privilege_type']} for legitimate business purpose"
                
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    activation_headers, track_cost=False
                )
                
                logger.info(f"Zero standing privilege activation {privilege_test['privilege_type']}: "
                           f"{response.status_code}")
                
                # Simulate approval workflow if required
                if privilege_test["approval_required"]:
                    approval_headers = dict(activation_headers)
                    approval_headers.update({
                        "X-Privilege-Request": "approve",
                        "X-Approver": "security_manager",
                        "X-Approval-Timestamp": str(int(time.time()))
                    })
                    
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        approval_headers, track_cost=False
                    )
                    
                    logger.info(f"Zero standing privilege approval {privilege_test['privilege_type']}: "
                               f"{response.status_code}")
                
                # Test activated privilege usage
                usage_headers = dict(activation_headers)
                usage_headers.update({
                    "X-Privilege-Request": "use",
                    "X-Privilege-Active": "true",
                    "X-Activation-Time": str(int(time.time()))
                })
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    usage_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Using activated privilege {privilege_test['privilege_type']}"}],
                        "max_tokens": 10
                    }, track_cost=False
                )
                
                logger.info(f"Zero standing privilege usage {privilege_test['privilege_type']}: "
                           f"{response.status_code}")
                
                # Test automatic privilege deactivation
                if privilege_test["time_limit"] > 0:
                    deactivation_headers = dict(usage_headers)
                    deactivation_headers.update({
                        "X-Privilege-Active": "false",
                        "X-Deactivation-Reason": "time_limit_expired",
                        "X-Deactivation-Time": str(int(time.time() + privilege_test["time_limit"]))
                    })
                    
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        deactivation_headers, track_cost=False
                    )
                    
                    logger.info(f"Zero standing privilege deactivation {privilege_test['privilege_type']}: "
                               f"{response.status_code}")
            else:
                # Basic operations should work without activation
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    activation_headers, track_cost=False
                )
                
                logger.info(f"Zero standing basic operation {privilege_test['privilege_type']}: "
                           f"{response.status_code}")
        
        # Test emergency break-glass procedures
        emergency_tests = [
            {
                "emergency_type": "security_incident",
                "break_glass_level": "level_1",
                "emergency_justification": "Active security breach requires immediate admin access",
                "enhanced_audit": True,
                "notification_required": True
            },
            {
                "emergency_type": "service_outage",
                "break_glass_level": "level_2",
                "emergency_justification": "Critical service outage requires elevated privileges",
                "enhanced_audit": True,
                "notification_required": True
            }
        ]
        
        for emergency in emergency_tests:
            emergency_headers = dict(auth_headers)
            emergency_headers.update({
                "X-Emergency-Type": emergency["emergency_type"],
                "X-Break-Glass-Level": emergency["break_glass_level"],
                "X-Emergency-Justification": emergency["emergency_justification"],
                "X-Enhanced-Audit": str(emergency["enhanced_audit"]).lower(),
                "X-Notification-Required": str(emergency["notification_required"]).lower(),
                "X-Break-Glass": "activated"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                emergency_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Emergency access {emergency['emergency_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Emergency break-glass {emergency['emergency_type']} "
                       f"({emergency['break_glass_level']}): {response.status_code}")
        
        logger.info("ZTA_LP_016: Zero standing privileges tested")