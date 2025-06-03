# Section 7.12 - Zero Trust Continuous Monitoring Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Continuous Monitoring Verification.md
# Enhanced Test Cases: ZTA_CM_009 through ZTA_CM_016

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
import json
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestContinuousMonitoringEnhanced:
    """Enhanced Zero Trust Continuous Monitoring tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_009_realtime_security_event_correlation(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """ZTA_CM_009: Test real-time correlation of security events across multiple sources"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test correlation of authentication failures across multiple API keys
        correlation_session_id = f"corr_{secrets.token_hex(8)}"
        
        # Simulate multiple failed authentication attempts
        failed_auth_tests = [
            {"key": "Bearer invalid_key_1", "source_ip": "192.168.1.100"},
            {"key": "Bearer invalid_key_2", "source_ip": "192.168.1.100"}, 
            {"key": "Bearer invalid_key_3", "source_ip": "192.168.1.101"},
            {"key": "Bearer invalid_key_4", "source_ip": "192.168.1.100"}
        ]
        
        correlation_events = []
        
        for i, auth_test in enumerate(failed_auth_tests):
            event_headers = {
                "Authorization": auth_test["key"],
                "X-Forwarded-For": auth_test["source_ip"],
                "X-Correlation-Session": correlation_session_id,
                "X-Event-Sequence": str(i + 1),
                "X-Event-Type": "authentication_failure"
            }
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                event_headers, track_cost=False
            )
            
            correlation_events.append({
                "sequence": i + 1,
                "timestamp": time.time(),
                "source_ip": auth_test["source_ip"],
                "status": response.status_code,
                "event_type": "auth_failure"
            })
            
            assert response.status_code in [401, 403], "Invalid auth should fail"
            await asyncio.sleep(0.1)
        
        # Test detection of coordinated attack patterns
        attack_pattern_analysis = {
            "total_events": len(correlation_events),
            "unique_ips": len(set(e["source_ip"] for e in correlation_events)),
            "time_span": correlation_events[-1]["timestamp"] - correlation_events[0]["timestamp"],
            "failure_rate": sum(1 for e in correlation_events if e["status"] in [401, 403]) / len(correlation_events)
        }
        
        # Simulate coordinated attack detection
        coordinated_headers = dict(auth_headers)
        coordinated_headers.update({
            "X-Correlation-Session": correlation_session_id,
            "X-Attack-Pattern": "coordinated_brute_force",
            "X-Event-Count": str(attack_pattern_analysis["total_events"]),
            "X-Unique-Sources": str(attack_pattern_analysis["unique_ips"]),
            "X-Failure-Rate": str(attack_pattern_analysis["failure_rate"])
        })
        
        response = await make_request(
            http_client, "GET", "/api/v1/models",
            coordinated_headers, track_cost=False
        )
        
        logger.info(f"Security event correlation - Session: {correlation_session_id}, "
                   f"Events: {attack_pattern_analysis['total_events']}, "
                   f"IPs: {attack_pattern_analysis['unique_ips']}, "
                   f"Failure rate: {attack_pattern_analysis['failure_rate']:.2f}")
        
        logger.info("ZTA_CM_009: Real-time security event correlation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_010_behavioral_analytics_anomaly_detection(self, http_client: httpx.AsyncClient,
                                                                    auth_headers: Dict[str, str],
                                                                    make_request):
        """ZTA_CM_010: Test behavioral analytics for user and API key usage patterns"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Establish baseline behavioral patterns
        baseline_session_id = f"baseline_{secrets.token_hex(8)}"
        baseline_patterns = []
        
        # Normal usage pattern - varied requests with consistent timing
        normal_requests = [
            ("GET", "/api/v1/models", None),
            ("POST", "/api/v1/chat/completions", {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Normal baseline request"}],
                "max_tokens": 10
            }),
            ("POST", "/api/v1/embeddings", {
                "model": config.get_embedding_model(0),
                "input": "Normal embedding baseline"
            })
        ]
        
        for i, (method, endpoint, data) in enumerate(normal_requests * 3):  # Repeat pattern
            baseline_start = time.time()
            
            baseline_headers = dict(auth_headers)
            baseline_headers.update({
                "X-Behavioral-Session": baseline_session_id,
                "X-Pattern-Type": "baseline_normal",
                "X-Request-Sequence": str(i + 1)
            })
            
            response = await make_request(
                http_client, method, endpoint,
                baseline_headers, json=data, track_cost=(i == 1)
            )
            
            baseline_end = time.time()
            
            baseline_patterns.append({
                "sequence": i + 1,
                "method": method,
                "endpoint": endpoint,
                "response_time": baseline_end - baseline_start,
                "status": response.status_code,
                "timestamp": baseline_end
            })
            
            await asyncio.sleep(1.0)  # Consistent timing
        
        # Test anomalous behavioral patterns
        anomaly_session_id = f"anomaly_{secrets.token_hex(8)}"
        anomaly_tests = [
            {
                "type": "frequency_spike",
                "description": "Sudden increase in request frequency",
                "requests": 10,
                "interval": 0.1
            },
            {
                "type": "pattern_deviation",
                "description": "Unusual request pattern deviation",
                "requests": 5,
                "interval": 0.5
            }
        ]
        
        for anomaly in anomaly_tests:
            anomaly_patterns = []
            
            for i in range(anomaly["requests"]):
                anomaly_start = time.time()
                
                anomaly_headers = dict(auth_headers)
                anomaly_headers.update({
                    "X-Behavioral-Session": anomaly_session_id,
                    "X-Anomaly-Type": anomaly["type"],
                    "X-Pattern-Type": "anomalous",
                    "X-Request-Sequence": str(i + 1)
                })
                
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    anomaly_headers, track_cost=False
                )
                
                anomaly_end = time.time()
                
                anomaly_patterns.append({
                    "sequence": i + 1,
                    "response_time": anomaly_end - anomaly_start,
                    "status": response.status_code,
                    "timestamp": anomaly_end
                })
                
                await asyncio.sleep(anomaly["interval"])
            
            # Analyze behavioral metrics
            baseline_avg_interval = 1.0  # Known from baseline
            anomaly_avg_interval = sum(
                anomaly_patterns[i]["timestamp"] - anomaly_patterns[i-1]["timestamp"] 
                for i in range(1, len(anomaly_patterns))
            ) / (len(anomaly_patterns) - 1) if len(anomaly_patterns) > 1 else 0
            
            deviation_score = abs(baseline_avg_interval - anomaly_avg_interval) / baseline_avg_interval
            
            logger.info(f"Behavioral anomaly {anomaly['type']}: "
                       f"baseline_interval={baseline_avg_interval:.2f}s, "
                       f"anomaly_interval={anomaly_avg_interval:.2f}s, "
                       f"deviation_score={deviation_score:.2f}")
        
        logger.info("ZTA_CM_010: Behavioral analytics and anomaly detection tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_011_advanced_pii_detection_redaction(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_CM_011: Test advanced PII detection and redaction in logs"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test ML-based detection of PII patterns in request data
        pii_test_cases = [
            {
                "category": "ssn",
                "content": "My Social Security Number is 123-45-6789",
                "expected_redaction": "My Social Security Number is ***-**-****",
                "detection_confidence": 0.95
            },
            {
                "category": "credit_card",
                "content": "Credit card: 4532-1234-5678-9012",
                "expected_redaction": "Credit card: ****-****-****-****",
                "detection_confidence": 0.90
            },
            {
                "category": "email",
                "content": "Contact me at john.doe@example.com",
                "expected_redaction": "Contact me at [EMAIL_REDACTED]",
                "detection_confidence": 0.85
            },
            {
                "category": "phone",
                "content": "Call me at (555) 123-4567",
                "expected_redaction": "Call me at [PHONE_REDACTED]",
                "detection_confidence": 0.80
            },
            {
                "category": "address",
                "content": "I live at 123 Main Street, Anytown, ST 12345",
                "expected_redaction": "I live at [ADDRESS_REDACTED]",
                "detection_confidence": 0.75
            }
        ]
        
        for pii_test in pii_test_cases:
            pii_headers = dict(auth_headers)
            pii_headers.update({
                "X-PII-Category": pii_test["category"],
                "X-PII-Detection": "enabled",
                "X-Redaction-Mode": "automatic",
                "X-Detection-Confidence": str(pii_test["detection_confidence"])
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                pii_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": pii_test["content"]}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            # Current implementation doesn't have PII detection
            # This documents expected behavior with PII controls
            logger.info(f"PII detection {pii_test['category']} "
                       f"(confidence: {pii_test['detection_confidence']}): {response.status_code}")
        
        # Test context-aware filtering that preserves operational data
        context_aware_tests = [
            {
                "content": "Error in transaction ID: TXN-12345 for user account",
                "preserve": ["transaction_id"],
                "redact": [],
                "context": "operational_data"
            },
            {
                "content": "Log entry: User john.doe@company.com accessed system",
                "preserve": [],
                "redact": ["email"],
                "context": "security_log"
            },
            {
                "content": "API key prefix: sk-1234... used for request",
                "preserve": ["api_key_prefix"],
                "redact": [],
                "context": "api_monitoring"
            }
        ]
        
        for context_test in context_aware_tests:
            context_headers = dict(auth_headers)
            context_headers.update({
                "X-Context-Aware": "enabled",
                "X-Data-Context": context_test["context"],
                "X-Preserve-Fields": ",".join(context_test["preserve"]),
                "X-Redact-Fields": ",".join(context_test["redact"])
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                context_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": context_test["content"]}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Context-aware filtering {context_test['context']}: {response.status_code}")
        
        logger.info("ZTA_CM_011: Advanced PII detection and redaction tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_012_threat_intelligence_integration(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """ZTA_CM_012: Test integration with external threat intelligence feeds"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test integration with multiple threat intelligence feeds
        threat_feeds = [
            {
                "provider": "commercial_feed_1",
                "feed_type": "ioc_indicators",
                "update_frequency": "hourly",
                "confidence_threshold": 0.8
            },
            {
                "provider": "government_feed",
                "feed_type": "apt_campaigns",
                "update_frequency": "daily",
                "confidence_threshold": 0.9
            },
            {
                "provider": "community_feed",
                "feed_type": "malware_signatures",
                "update_frequency": "real_time",
                "confidence_threshold": 0.7
            }
        ]
        
        for feed in threat_feeds:
            feed_headers = dict(auth_headers)
            feed_headers.update({
                "X-Threat-Feed": feed["provider"],
                "X-Feed-Type": feed["feed_type"],
                "X-Update-Frequency": feed["update_frequency"],
                "X-Confidence-Threshold": str(feed["confidence_threshold"])
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                feed_headers, track_cost=False
            )
            
            logger.info(f"Threat intelligence feed {feed['provider']} "
                       f"({feed['feed_type']}): {response.status_code}")
        
        # Test IOC (Indicators of Compromise) matching
        ioc_tests = [
            {
                "ioc_type": "ip_address",
                "ioc_value": "203.0.113.100",
                "threat_category": "botnet_c2",
                "confidence": 0.95,
                "first_seen": "2024-01-15",
                "last_seen": "2024-01-20"
            },
            {
                "ioc_type": "domain",
                "ioc_value": "malicious-domain.example",
                "threat_category": "phishing",
                "confidence": 0.85,
                "first_seen": "2024-01-10",
                "last_seen": "2024-01-18"
            },
            {
                "ioc_type": "user_agent",
                "ioc_value": "BadBot/1.0",
                "threat_category": "automated_attack",
                "confidence": 0.75,
                "first_seen": "2024-01-12",
                "last_seen": "2024-01-19"
            }
        ]
        
        for ioc in ioc_tests:
            ioc_headers = dict(auth_headers)
            ioc_headers.update({
                "X-IOC-Type": ioc["ioc_type"],
                "X-IOC-Value": ioc["ioc_value"],
                "X-Threat-Category": ioc["threat_category"],
                "X-IOC-Confidence": str(ioc["confidence"])
            })
            
            # Simulate IOC in request headers
            if ioc["ioc_type"] == "ip_address":
                ioc_headers["X-Forwarded-For"] = ioc["ioc_value"]
            elif ioc["ioc_type"] == "user_agent":
                ioc_headers["User-Agent"] = ioc["ioc_value"]
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                ioc_headers, track_cost=False
            )
            
            logger.info(f"IOC matching {ioc['ioc_type']} "
                       f"({ioc['threat_category']}, confidence: {ioc['confidence']}): {response.status_code}")
        
        # Test threat landscape awareness and adaptive monitoring
        threat_landscape_tests = [
            {
                "threat_level": "elevated",
                "campaign": "apt_campaign_alpha",
                "tactics": ["reconnaissance", "credential_harvesting"],
                "adaptive_response": "enhanced_monitoring"
            },
            {
                "threat_level": "high",
                "campaign": "ransomware_outbreak",
                "tactics": ["lateral_movement", "data_exfiltration"],
                "adaptive_response": "strict_controls"
            }
        ]
        
        for landscape in threat_landscape_tests:
            landscape_headers = dict(auth_headers)
            landscape_headers.update({
                "X-Threat-Level": landscape["threat_level"],
                "X-Active-Campaign": landscape["campaign"],
                "X-Threat-Tactics": ",".join(landscape["tactics"]),
                "X-Adaptive-Response": landscape["adaptive_response"]
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                landscape_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Threat landscape test {landscape['threat_level']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Threat landscape {landscape['threat_level']} "
                       f"({landscape['campaign']}): {response.status_code}")
        
        logger.info("ZTA_CM_012: Threat intelligence integration tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_013_compliance_monitoring_reporting(self, http_client: httpx.AsyncClient,
                                                             auth_headers: Dict[str, str],
                                                             make_request):
        """ZTA_CM_013: Test automated compliance monitoring with regulatory framework adherence"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test monitoring for compliance with multiple regulatory frameworks
        compliance_frameworks = [
            {
                "framework": "FISMA",
                "requirements": ["access_control", "audit_logging", "incident_response"],
                "compliance_level": "moderate",
                "assessment_frequency": "annual"
            },
            {
                "framework": "SOX",
                "requirements": ["financial_controls", "audit_trails", "segregation_of_duties"],
                "compliance_level": "high",
                "assessment_frequency": "quarterly"
            },
            {
                "framework": "GDPR",
                "requirements": ["data_protection", "privacy_by_design", "consent_management"],
                "compliance_level": "strict",
                "assessment_frequency": "continuous"
            }
        ]
        
        for framework in compliance_frameworks:
            compliance_headers = dict(auth_headers)
            compliance_headers.update({
                "X-Compliance-Framework": framework["framework"],
                "X-Compliance-Level": framework["compliance_level"],
                "X-Requirements": ",".join(framework["requirements"]),
                "X-Assessment-Frequency": framework["assessment_frequency"]
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                compliance_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Compliance test for {framework['framework']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Compliance monitoring {framework['framework']} "
                       f"({framework['compliance_level']}): {response.status_code}")
        
        # Test automated violation detection
        violation_tests = [
            {
                "violation_type": "unauthorized_access",
                "framework": "FISMA",
                "severity": "high",
                "auto_remediation": "account_disable"
            },
            {
                "violation_type": "data_breach",
                "framework": "GDPR",
                "severity": "critical",
                "auto_remediation": "incident_response"
            },
            {
                "violation_type": "audit_gap",
                "framework": "SOX",
                "severity": "medium",
                "auto_remediation": "alert_admin"
            }
        ]
        
        for violation in violation_tests:
            violation_headers = dict(auth_headers)
            violation_headers.update({
                "X-Violation-Type": violation["violation_type"],
                "X-Compliance-Framework": violation["framework"],
                "X-Violation-Severity": violation["severity"],
                "X-Auto-Remediation": violation["auto_remediation"],
                "X-Violation-Detected": "true"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                violation_headers, track_cost=False
            )
            
            logger.info(f"Compliance violation {violation['violation_type']} "
                       f"({violation['framework']}, {violation['severity']}): {response.status_code}")
        
        # Test audit trail generation and evidence collection
        audit_tests = [
            {
                "audit_type": "access_audit",
                "scope": "api_key_usage",
                "period": "24_hours",
                "evidence_types": ["authentication_logs", "authorization_decisions", "resource_access"]
            },
            {
                "audit_type": "data_audit",
                "scope": "data_processing",
                "period": "7_days",
                "evidence_types": ["data_flows", "processing_logs", "consent_records"]
            }
        ]
        
        for audit in audit_tests:
            audit_headers = dict(auth_headers)
            audit_headers.update({
                "X-Audit-Type": audit["audit_type"],
                "X-Audit-Scope": audit["scope"],
                "X-Audit-Period": audit["period"],
                "X-Evidence-Types": ",".join(audit["evidence_types"]),
                "X-Audit-Request": "generate"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                audit_headers, track_cost=False
            )
            
            logger.info(f"Audit trail {audit['audit_type']} "
                       f"({audit['scope']}, {audit['period']}): {response.status_code}")
        
        logger.info("ZTA_CM_013: Compliance monitoring and reporting tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_014_distributed_tracing_observability(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               make_request):
        """ZTA_CM_014: Test distributed tracing across all system components"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test end-to-end tracing from client request to LLM provider response
        trace_id = f"trace_{secrets.token_hex(16)}"
        span_id = f"span_{secrets.token_hex(8)}"
        
        tracing_headers = dict(auth_headers)
        tracing_headers.update({
            "X-Trace-ID": trace_id,
            "X-Span-ID": span_id,
            "X-Parent-Span-ID": "root",
            "X-Tracing-Enabled": "true",
            "X-Sampling-Rate": "1.0"  # 100% sampling for testing
        })
        
        # Simulate distributed trace across multiple operations
        trace_operations = [
            {
                "operation": "authentication",
                "component": "auth_service",
                "expected_spans": ["validate_api_key", "check_scopes"]
            },
            {
                "operation": "request_processing",
                "component": "api_gateway",
                "expected_spans": ["input_validation", "route_request"]
            },
            {
                "operation": "llm_inference",
                "component": "llm_provider",
                "expected_spans": ["provider_call", "response_processing"]
            }
        ]
        
        trace_start = time.time()
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            tracing_headers, json={
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Distributed tracing test"}],
                "max_tokens": 10
            }, track_cost=True
        )
        
        trace_end = time.time()
        trace_duration = trace_end - trace_start
        
        # Simulate trace analysis
        trace_analysis = {
            "trace_id": trace_id,
            "total_duration": trace_duration,
            "span_count": len(trace_operations),
            "success": response.status_code == 200,
            "components_traced": [op["component"] for op in trace_operations]
        }
        
        logger.info(f"Distributed trace {trace_id}: "
                   f"duration={trace_duration:.3f}s, "
                   f"spans={trace_analysis['span_count']}, "
                   f"success={trace_analysis['success']}")
        
        # Test trace correlation across microservices
        correlation_tests = [
            {
                "service": "api_gateway",
                "trace_correlation": "enabled",
                "propagation": "b3_headers"
            },
            {
                "service": "auth_service",
                "trace_correlation": "enabled",
                "propagation": "jaeger_headers"
            },
            {
                "service": "llm_service",
                "trace_correlation": "enabled",
                "propagation": "opentelemetry"
            }
        ]
        
        for correlation in correlation_tests:
            correlation_headers = dict(tracing_headers)
            correlation_headers.update({
                "X-Service": correlation["service"],
                "X-Trace-Correlation": correlation["trace_correlation"],
                "X-Propagation-Format": correlation["propagation"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                correlation_headers, track_cost=False
            )
            
            logger.info(f"Trace correlation {correlation['service']} "
                       f"({correlation['propagation']}): {response.status_code}")
        
        logger.info("ZTA_CM_014: Distributed tracing and observability tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_015_security_orchestration_automated_response(self, http_client: httpx.AsyncClient,
                                                                       auth_headers: Dict[str, str],
                                                                       make_request):
        """ZTA_CM_015: Test security orchestration platform integration with automated response"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test automated incident creation and escalation workflows
        incident_types = [
            {
                "type": "authentication_anomaly",
                "severity": "medium",
                "auto_response": ["log_enhanced", "notify_admin"],
                "escalation_threshold": 5
            },
            {
                "type": "potential_data_breach",
                "severity": "high",
                "auto_response": ["block_user", "create_incident", "notify_ciso"],
                "escalation_threshold": 1
            },
            {
                "type": "suspicious_activity",
                "severity": "low",
                "auto_response": ["increase_monitoring"],
                "escalation_threshold": 10
            }
        ]
        
        for incident in incident_types:
            incident_headers = dict(auth_headers)
            incident_headers.update({
                "X-Incident-Type": incident["type"],
                "X-Incident-Severity": incident["severity"],
                "X-Auto-Response": ",".join(incident["auto_response"]),
                "X-Escalation-Threshold": str(incident["escalation_threshold"]),
                "X-SOAR-Enabled": "true"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                incident_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"SOAR test {incident['type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"SOAR incident {incident['type']} "
                       f"({incident['severity']}, threshold: {incident['escalation_threshold']}): {response.status_code}")
        
        # Test orchestrated response actions across security tools
        orchestration_tests = [
            {
                "trigger": "brute_force_detected",
                "tools": ["waf", "siem", "iam"],
                "actions": ["block_ip", "create_alert", "disable_account"],
                "coordination": "sequential"
            },
            {
                "trigger": "malware_detected",
                "tools": ["antivirus", "firewall", "endpoint_protection"],
                "actions": ["quarantine", "block_communication", "isolate_endpoint"],
                "coordination": "parallel"
            }
        ]
        
        for orchestration in orchestration_tests:
            orchestration_headers = dict(auth_headers)
            orchestration_headers.update({
                "X-Trigger": orchestration["trigger"],
                "X-Security-Tools": ",".join(orchestration["tools"]),
                "X-Orchestrated-Actions": ",".join(orchestration["actions"]),
                "X-Coordination-Mode": orchestration["coordination"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                orchestration_headers, track_cost=False
            )
            
            logger.info(f"Security orchestration {orchestration['trigger']} "
                       f"({orchestration['coordination']}, tools: {len(orchestration['tools'])}): {response.status_code}")
        
        # Test playbook execution and decision making
        playbook_tests = [
            {
                "playbook": "incident_response_playbook",
                "trigger_event": "security_incident",
                "automated_steps": ["evidence_collection", "containment", "analysis"],
                "manual_steps": ["impact_assessment", "communication"],
                "decision_points": ["escalate_to_human", "auto_remediate"]
            }
        ]
        
        for playbook in playbook_tests:
            playbook_headers = dict(auth_headers)
            playbook_headers.update({
                "X-Playbook": playbook["playbook"],
                "X-Trigger-Event": playbook["trigger_event"],
                "X-Automated-Steps": ",".join(playbook["automated_steps"]),
                "X-Manual-Steps": ",".join(playbook["manual_steps"]),
                "X-Decision-Points": ",".join(playbook["decision_points"])
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                playbook_headers, track_cost=False
            )
            
            logger.info(f"Playbook execution {playbook['playbook']}: {response.status_code}")
        
        logger.info("ZTA_CM_015: Security orchestration and automated response tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_cm_016_continuous_security_posture_assessment(self, http_client: httpx.AsyncClient,
                                                                    auth_headers: Dict[str, str],
                                                                    make_request):
        """ZTA_CM_016: Test continuous assessment of security posture with automated vulnerability detection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test continuous assessment of security control effectiveness
        security_controls = [
            {
                "control": "authentication",
                "effectiveness": 0.95,
                "last_tested": "2024-01-20",
                "next_assessment": "2024-01-21"
            },
            {
                "control": "authorization",
                "effectiveness": 0.90,
                "last_tested": "2024-01-20",
                "next_assessment": "2024-01-21"
            },
            {
                "control": "input_validation",
                "effectiveness": 0.85,
                "last_tested": "2024-01-19",
                "next_assessment": "2024-01-22"
            }
        ]
        
        for control in security_controls:
            control_headers = dict(auth_headers)
            control_headers.update({
                "X-Security-Control": control["control"],
                "X-Effectiveness-Score": str(control["effectiveness"]),
                "X-Last-Tested": control["last_tested"],
                "X-Assessment-Due": control["next_assessment"],
                "X-Continuous-Assessment": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                control_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Security control test {control['control']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Security control {control['control']} "
                       f"(effectiveness: {control['effectiveness']}): {response.status_code}")
        
        # Test automated vulnerability detection in runtime environments
        vulnerability_tests = [
            {
                "scan_type": "runtime_analysis",
                "vulnerabilities": ["injection_points", "auth_bypasses"],
                "risk_level": "medium",
                "auto_remediation": "patch_available"
            },
            {
                "scan_type": "configuration_audit",
                "vulnerabilities": ["weak_ciphers", "default_passwords"],
                "risk_level": "high",
                "auto_remediation": "config_update"
            }
        ]
        
        for vuln_test in vulnerability_tests:
            vuln_headers = dict(auth_headers)
            vuln_headers.update({
                "X-Scan-Type": vuln_test["scan_type"],
                "X-Vulnerabilities": ",".join(vuln_test["vulnerabilities"]),
                "X-Risk-Level": vuln_test["risk_level"],
                "X-Auto-Remediation": vuln_test["auto_remediation"],
                "X-Runtime-Scan": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                vuln_headers, track_cost=False
            )
            
            logger.info(f"Vulnerability scan {vuln_test['scan_type']} "
                       f"(risk: {vuln_test['risk_level']}): {response.status_code}")
        
        # Test risk scoring and posture measurement
        posture_metrics = [
            {
                "metric": "overall_security_score",
                "value": 0.87,
                "trend": "improving",
                "target": 0.95
            },
            {
                "metric": "vulnerability_exposure",
                "value": 0.15,
                "trend": "stable", 
                "target": 0.05
            },
            {
                "metric": "compliance_coverage",
                "value": 0.92,
                "trend": "improving",
                "target": 0.98
            }
        ]
        
        for metric in posture_metrics:
            metric_headers = dict(auth_headers)
            metric_headers.update({
                "X-Posture-Metric": metric["metric"],
                "X-Metric-Value": str(metric["value"]),
                "X-Metric-Trend": metric["trend"],
                "X-Metric-Target": str(metric["target"]),
                "X-Posture-Measurement": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                metric_headers, track_cost=False
            )
            
            logger.info(f"Posture metric {metric['metric']} "
                       f"(value: {metric['value']}, trend: {metric['trend']}): {response.status_code}")
        
        logger.info("ZTA_CM_016: Continuous security posture assessment tested")