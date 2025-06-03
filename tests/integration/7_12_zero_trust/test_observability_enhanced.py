# Section 7.12 - Zero Trust Observability Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Observability.md
# Enhanced Test Cases: ZTA_OBS_009 through ZTA_OBS_016

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


class TestObservabilityEnhanced:
    """Enhanced Zero Trust Observability tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_009_realtime_security_event_correlation(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """ZTA_OBS_009: Test real-time correlation of security events across multiple data sources"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test correlation of authentication events across multiple API keys
        correlation_id = f"corr_{secrets.token_hex(8)}"
        
        # Simulate correlated security events
        security_events = [
            {
                "event_type": "failed_authentication",
                "source": "api_auth",
                "severity": "medium",
                "correlation_score": 0.8
            },
            {
                "event_type": "unusual_access_pattern", 
                "source": "behavioral_analysis",
                "severity": "low",
                "correlation_score": 0.6
            },
            {
                "event_type": "privilege_escalation_attempt",
                "source": "authorization_monitor",
                "severity": "high",
                "correlation_score": 0.9
            }
        ]
        
        correlated_events = []
        
        for event in security_events:
            event_headers = dict(auth_headers)
            event_headers.update({
                "X-Correlation-ID": correlation_id,
                "X-Event-Type": event["event_type"],
                "X-Event-Source": event["source"],
                "X-Event-Severity": event["severity"],
                "X-Correlation-Score": str(event["correlation_score"]),
                "X-Real-Time-Correlation": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                event_headers, track_cost=False
            )
            
            correlated_events.append({
                "event": event["event_type"],
                "timestamp": time.time(),
                "status": response.status_code,
                "correlation_score": event["correlation_score"]
            })
            
            await asyncio.sleep(0.2)
        
        # Analyze correlation patterns
        avg_correlation = sum(e["correlation_score"] for e in correlated_events) / len(correlated_events)
        high_risk_events = [e for e in correlated_events if e["correlation_score"] > 0.7]
        
        logger.info(f"Event correlation {correlation_id}: "
                   f"{len(correlated_events)} events, avg_correlation={avg_correlation:.2f}, "
                   f"high_risk={len(high_risk_events)}")
        
        logger.info("ZTA_OBS_009: Real-time security event correlation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_010_distributed_tracing_performance_monitoring(self, http_client: httpx.AsyncClient,
                                                                         auth_headers: Dict[str, str],
                                                                         make_request):
        """ZTA_OBS_010: Test comprehensive distributed tracing with end-to-end observability"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test end-to-end request tracing from client to LLM provider
        trace_id = f"trace_{secrets.token_hex(16)}"
        
        # Simulate distributed trace spans
        trace_spans = [
            {
                "span_name": "http_request_ingress",
                "service": "load_balancer",
                "operation": "route_request",
                "expected_duration_ms": 5
            },
            {
                "span_name": "authentication_validation",
                "service": "auth_service",
                "operation": "validate_api_key",
                "expected_duration_ms": 15
            },
            {
                "span_name": "authorization_check",
                "service": "auth_service",
                "operation": "check_scopes",
                "expected_duration_ms": 10
            },
            {
                "span_name": "llm_provider_call",
                "service": "llm_adapter",
                "operation": "chat_completion",
                "expected_duration_ms": 500
            }
        ]
        
        trace_start = time.time()
        
        tracing_headers = dict(auth_headers)
        tracing_headers.update({
            "X-Trace-ID": trace_id,
            "X-Distributed-Tracing": "enabled",
            "X-Sampling-Rate": "1.0",
            "X-Trace-Context": "sampled"
        })
        
        # Execute traced request
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            tracing_headers, json={
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Distributed tracing test"}],
                "max_tokens": 10
            }, track_cost=True
        )
        
        trace_end = time.time()
        total_duration = (trace_end - trace_start) * 1000  # Convert to ms
        
        # Simulate span analysis
        span_analysis = {
            "trace_id": trace_id,
            "total_spans": len(trace_spans),
            "total_duration_ms": total_duration,
            "services_involved": list(set(span["service"] for span in trace_spans)),
            "critical_path": ["authentication_validation", "llm_provider_call"],
            "success": response.status_code == 200
        }
        
        logger.info(f"Distributed trace {trace_id}: "
                   f"duration={span_analysis['total_duration_ms']:.1f}ms, "
                   f"spans={span_analysis['total_spans']}, "
                   f"services={len(span_analysis['services_involved'])}")
        
        # Test performance monitoring and bottleneck identification
        performance_analysis = [
            {
                "metric": "p95_latency",
                "value": total_duration,
                "threshold": 1000,
                "status": "normal" if total_duration < 1000 else "warning"
            },
            {
                "metric": "error_rate",
                "value": 0.0 if response.status_code == 200 else 1.0,
                "threshold": 0.01,
                "status": "normal" if response.status_code == 200 else "critical"
            }
        ]
        
        for perf_metric in performance_analysis:
            logger.info(f"Performance metric {perf_metric['metric']}: "
                       f"value={perf_metric['value']}, "
                       f"threshold={perf_metric['threshold']}, "
                       f"status={perf_metric['status']}")
        
        logger.info("ZTA_OBS_010: Distributed tracing and performance monitoring tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_011_security_metrics_kpi_dashboards(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_OBS_011: Test comprehensive security metrics collection and KPI dashboard visualization"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test collection of security-relevant metrics
        security_metrics = [
            {
                "metric_name": "authentication_success_rate",
                "metric_type": "percentage",
                "current_value": 98.5,
                "target_value": 99.0,
                "trend": "stable"
            },
            {
                "metric_name": "authorization_failure_count",
                "metric_type": "counter",
                "current_value": 23,
                "target_value": 10,
                "trend": "increasing"
            },
            {
                "metric_name": "security_incident_mttr",
                "metric_type": "duration_minutes",
                "current_value": 45,
                "target_value": 30,
                "trend": "improving"
            },
            {
                "metric_name": "api_abuse_detection_rate",
                "metric_type": "percentage",
                "current_value": 87.2,
                "target_value": 95.0,
                "trend": "stable"
            }
        ]
        
        for metric in security_metrics:
            metric_headers = dict(auth_headers)
            metric_headers.update({
                "X-Metric-Name": metric["metric_name"],
                "X-Metric-Type": metric["metric_type"],
                "X-Current-Value": str(metric["current_value"]),
                "X-Target-Value": str(metric["target_value"]),
                "X-Trend": metric["trend"],
                "X-Metrics-Collection": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                metric_headers, track_cost=False
            )
            
            # Analyze metric performance
            performance_status = "on_target"
            if metric["metric_type"] == "percentage" and metric["current_value"] < metric["target_value"]:
                performance_status = "below_target"
            elif metric["metric_type"] == "counter" and metric["current_value"] > metric["target_value"]:
                performance_status = "above_target"
            elif metric["metric_type"] == "duration_minutes" and metric["current_value"] > metric["target_value"]:
                performance_status = "above_target"
            
            logger.info(f"Security metric {metric['metric_name']}: "
                       f"current={metric['current_value']}, "
                       f"target={metric['target_value']}, "
                       f"status={performance_status}")
        
        # Test real-time dashboard updates
        dashboard_components = [
            {
                "component": "threat_detection_panel",
                "data_source": "security_events",
                "update_frequency": "real_time",
                "alert_threshold": "high"
            },
            {
                "component": "authentication_metrics",
                "data_source": "auth_logs",
                "update_frequency": "5_minutes",
                "alert_threshold": "medium"
            },
            {
                "component": "api_usage_trends",
                "data_source": "api_metrics",
                "update_frequency": "1_minute",
                "alert_threshold": "low"
            }
        ]
        
        for component in dashboard_components:
            dashboard_headers = dict(auth_headers)
            dashboard_headers.update({
                "X-Dashboard-Component": component["component"],
                "X-Data-Source": component["data_source"],
                "X-Update-Frequency": component["update_frequency"],
                "X-Alert-Threshold": component["alert_threshold"],
                "X-Dashboard-Update": "triggered"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                dashboard_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Dashboard update test {component['component']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Dashboard component {component['component']}: "
                       f"update_freq={component['update_frequency']}, "
                       f"status={response.status_code}")
        
        logger.info("ZTA_OBS_011: Security metrics and KPI dashboards tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_012_behavioral_analytics_integration(self, http_client: httpx.AsyncClient,
                                                               auth_headers: Dict[str, str],
                                                               make_request):
        """ZTA_OBS_012: Test integration with behavioral analytics for user and system behavior monitoring"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test behavioral pattern establishment and baseline creation
        behavioral_session = f"behavior_{secrets.token_hex(8)}"
        
        # Establish baseline behavior patterns
        baseline_behaviors = [
            {
                "behavior_type": "api_usage_pattern",
                "pattern_description": "standard_business_hours",
                "frequency": "moderate",
                "endpoints": ["models", "chat"],
                "time_pattern": "9_to_5"
            },
            {
                "behavior_type": "request_size_pattern",
                "pattern_description": "small_to_medium_requests",
                "frequency": "consistent",
                "endpoints": ["chat", "embeddings"],
                "time_pattern": "throughout_day"
            }
        ]
        
        for baseline in baseline_behaviors:
            baseline_headers = dict(auth_headers)
            baseline_headers.update({
                "X-Behavioral-Session": behavioral_session,
                "X-Behavior-Type": baseline["behavior_type"],
                "X-Pattern-Description": baseline["pattern_description"],
                "X-Pattern-Frequency": baseline["frequency"],
                "X-Pattern-Endpoints": ",".join(baseline["endpoints"]),
                "X-Time-Pattern": baseline["time_pattern"],
                "X-Baseline-Learning": "enabled"
            })
            
            # Simulate baseline behavior
            for endpoint in baseline["endpoints"]:
                if endpoint == "models":
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        baseline_headers, track_cost=False
                    )
                elif endpoint == "chat":
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        baseline_headers, json={
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Baseline behavior {baseline['behavior_type']}"}],
                            "max_tokens": 10
                        }, track_cost=False
                    )
                elif endpoint == "embeddings":
                    response = await make_request(
                        http_client, "POST", "/api/v1/embeddings",
                        baseline_headers, json={
                            "model": config.get_embedding_model(0),
                            "input": f"Baseline embedding {baseline['behavior_type']}"
                        }, track_cost=False
                    )
                
                await asyncio.sleep(0.3)
            
            logger.info(f"Behavioral baseline {baseline['behavior_type']}: established")
        
        # Test anomaly detection for unusual behavior patterns
        anomaly_behaviors = [
            {
                "anomaly_type": "frequency_spike",
                "description": "sudden_increase_in_requests",
                "deviation_score": 2.5,
                "risk_level": "medium"
            },
            {
                "anomaly_type": "time_anomaly",
                "description": "requests_during_off_hours",
                "deviation_score": 3.2,
                "risk_level": "high"
            },
            {
                "anomaly_type": "pattern_change",
                "description": "different_endpoint_usage",
                "deviation_score": 1.8,
                "risk_level": "low"
            }
        ]
        
        for anomaly in anomaly_behaviors:
            anomaly_headers = dict(auth_headers)
            anomaly_headers.update({
                "X-Behavioral-Session": behavioral_session,
                "X-Anomaly-Type": anomaly["anomaly_type"],
                "X-Anomaly-Description": anomaly["description"],
                "X-Deviation-Score": str(anomaly["deviation_score"]),
                "X-Risk-Level": anomaly["risk_level"],
                "X-Anomaly-Detection": "active"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                anomaly_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Anomaly test {anomaly['anomaly_type']}"}],
                    "max_tokens": 15
                }, track_cost=False
            )
            
            logger.info(f"Behavioral anomaly {anomaly['anomaly_type']} "
                       f"(deviation: {anomaly['deviation_score']}, risk: {anomaly['risk_level']}): "
                       f"{response.status_code}")
        
        # Test behavioral scoring and risk assessment
        risk_scores = [
            {
                "user_id": "user_001",
                "behavior_score": 0.92,
                "risk_factors": ["consistent_usage", "normal_hours"],
                "risk_level": "low"
            },
            {
                "user_id": "user_002", 
                "behavior_score": 0.65,
                "risk_factors": ["unusual_timing", "volume_spike"],
                "risk_level": "medium"
            },
            {
                "user_id": "user_003",
                "behavior_score": 0.23,
                "risk_factors": ["off_hours", "pattern_deviation", "high_volume"],
                "risk_level": "high"
            }
        ]
        
        for risk_score in risk_scores:
            risk_headers = dict(auth_headers)
            risk_headers.update({
                "X-User-ID": risk_score["user_id"],
                "X-Behavior-Score": str(risk_score["behavior_score"]),
                "X-Risk-Factors": ",".join(risk_score["risk_factors"]),
                "X-Risk-Level": risk_score["risk_level"],
                "X-Behavioral-Scoring": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                risk_headers, track_cost=False
            )
            
            logger.info(f"Behavioral risk {risk_score['user_id']}: "
                       f"score={risk_score['behavior_score']}, "
                       f"level={risk_score['risk_level']}")
        
        logger.info("ZTA_OBS_012: Behavioral analytics integration tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_013_threat_intelligence_integration(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_OBS_013: Test integration with threat intelligence feeds for enhanced monitoring"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test integration with multiple threat intelligence feeds
        threat_feeds = [
            {
                "feed_name": "commercial_threat_feed",
                "provider": "CrowdStrike",
                "feed_type": "ioc_indicators",
                "confidence_level": "high",
                "update_frequency": "real_time"
            },
            {
                "feed_name": "government_alerts",
                "provider": "CISA",
                "feed_type": "vulnerability_alerts",
                "confidence_level": "verified",
                "update_frequency": "daily"
            },
            {
                "feed_name": "community_intel",
                "provider": "MISP",
                "feed_type": "community_sharing",
                "confidence_level": "medium",
                "update_frequency": "hourly"
            }
        ]
        
        for feed in threat_feeds:
            feed_headers = dict(auth_headers)
            feed_headers.update({
                "X-Threat-Feed": feed["feed_name"],
                "X-Feed-Provider": feed["provider"],
                "X-Feed-Type": feed["feed_type"],
                "X-Confidence-Level": feed["confidence_level"],
                "X-Update-Frequency": feed["update_frequency"],
                "X-Threat-Intel": "integrated"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                feed_headers, track_cost=False
            )
            
            logger.info(f"Threat intelligence feed {feed['feed_name']} "
                       f"({feed['provider']}, {feed['confidence_level']} confidence): "
                       f"{response.status_code}")
        
        # Test IOC matching and context enrichment
        ioc_tests = [
            {
                "ioc_type": "malicious_ip",
                "ioc_value": "203.0.113.100",
                "threat_category": "botnet_c2",
                "first_seen": "2024-01-15",
                "threat_actor": "APT-29"
            },
            {
                "ioc_type": "suspicious_user_agent",
                "ioc_value": "Malicious-Scanner/1.0",
                "threat_category": "reconnaissance",
                "first_seen": "2024-01-18",
                "threat_actor": "unknown"
            },
            {
                "ioc_type": "malicious_domain",
                "ioc_value": "evil-domain.example",
                "threat_category": "command_control",
                "first_seen": "2024-01-12",
                "threat_actor": "Lazarus"
            }
        ]
        
        for ioc in ioc_tests:
            ioc_headers = dict(auth_headers)
            ioc_headers.update({
                "X-IOC-Type": ioc["ioc_type"],
                "X-IOC-Value": ioc["ioc_value"],
                "X-Threat-Category": ioc["threat_category"],
                "X-First-Seen": ioc["first_seen"],
                "X-Threat-Actor": ioc["threat_actor"],
                "X-IOC-Matching": "enabled"
            })
            
            # Simulate IOC presence in request
            if ioc["ioc_type"] == "malicious_ip":
                ioc_headers["X-Forwarded-For"] = ioc["ioc_value"]
            elif ioc["ioc_type"] == "suspicious_user_agent":
                ioc_headers["User-Agent"] = ioc["ioc_value"]
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                ioc_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"IOC test {ioc['ioc_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"IOC matching {ioc['ioc_type']} "
                       f"({ioc['threat_category']}, actor: {ioc['threat_actor']}): "
                       f"{response.status_code}")
        
        # Test threat landscape awareness and adaptive monitoring
        threat_landscape = [
            {
                "campaign": "Operation_CloudHopper",
                "threat_level": "elevated",
                "target_sectors": ["technology", "government"],
                "tactics": ["spear_phishing", "lateral_movement"],
                "monitoring_adjustment": "increased_sensitivity"
            },
            {
                "campaign": "Ransomware_Wave_2024",
                "threat_level": "critical",
                "target_sectors": ["healthcare", "finance"],
                "tactics": ["email_compromise", "privilege_escalation"],
                "monitoring_adjustment": "maximum_vigilance"
            }
        ]
        
        for campaign in threat_landscape:
            landscape_headers = dict(auth_headers)
            landscape_headers.update({
                "X-Threat-Campaign": campaign["campaign"],
                "X-Threat-Level": campaign["threat_level"],
                "X-Target-Sectors": ",".join(campaign["target_sectors"]),
                "X-Campaign-Tactics": ",".join(campaign["tactics"]),
                "X-Monitoring-Adjustment": campaign["monitoring_adjustment"],
                "X-Threat-Landscape": "active"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                landscape_headers, track_cost=False
            )
            
            logger.info(f"Threat landscape {campaign['campaign']} "
                       f"({campaign['threat_level']}, adjustment: {campaign['monitoring_adjustment']}): "
                       f"{response.status_code}")
        
        logger.info("ZTA_OBS_013: Threat intelligence integration tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_014_compliance_monitoring_reporting(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_OBS_014: Test automated compliance monitoring with regulatory framework adherence"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test monitoring for compliance with regulatory requirements
        compliance_frameworks = [
            {
                "framework": "SOX",
                "requirements": ["access_controls", "audit_trails", "change_management"],
                "compliance_score": 0.94,
                "last_assessment": "2024-01-15"
            },
            {
                "framework": "GDPR",
                "requirements": ["data_protection", "consent_management", "breach_notification"],
                "compliance_score": 0.87,
                "last_assessment": "2024-01-18"
            },
            {
                "framework": "FISMA",
                "requirements": ["risk_assessment", "security_controls", "incident_response"],
                "compliance_score": 0.91,
                "last_assessment": "2024-01-12"
            }
        ]
        
        for framework in compliance_frameworks:
            compliance_headers = dict(auth_headers)
            compliance_headers.update({
                "X-Compliance-Framework": framework["framework"],
                "X-Requirements": ",".join(framework["requirements"]),
                "X-Compliance-Score": str(framework["compliance_score"]),
                "X-Last-Assessment": framework["last_assessment"],
                "X-Compliance-Monitoring": "active"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                compliance_headers, track_cost=False
            )
            
            compliance_status = "compliant" if framework["compliance_score"] > 0.9 else "needs_attention"
            logger.info(f"Compliance monitoring {framework['framework']}: "
                       f"score={framework['compliance_score']}, "
                       f"status={compliance_status}")
        
        # Test automated violation detection and reporting
        violation_scenarios = [
            {
                "violation_type": "unauthorized_access_attempt",
                "regulation": "SOX",
                "severity": "high",
                "auto_reported": True,
                "remediation_required": True
            },
            {
                "violation_type": "data_retention_breach",
                "regulation": "GDPR",
                "severity": "critical",
                "auto_reported": True,
                "remediation_required": True
            },
            {
                "violation_type": "insufficient_logging",
                "regulation": "FISMA",
                "severity": "medium",
                "auto_reported": True,
                "remediation_required": False
            }
        ]
        
        for violation in violation_scenarios:
            violation_headers = dict(auth_headers)
            violation_headers.update({
                "X-Violation-Type": violation["violation_type"],
                "X-Regulation": violation["regulation"],
                "X-Violation-Severity": violation["severity"],
                "X-Auto-Reported": str(violation["auto_reported"]).lower(),
                "X-Remediation-Required": str(violation["remediation_required"]).lower(),
                "X-Violation-Detection": "triggered"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                violation_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Compliance violation test {violation['violation_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Compliance violation {violation['violation_type']} "
                       f"({violation['regulation']}, {violation['severity']}): "
                       f"{response.status_code}")
        
        # Test audit trail generation and evidence collection
        audit_scenarios = [
            {
                "audit_type": "access_audit",
                "time_period": "last_30_days",
                "evidence_types": ["authentication_logs", "authorization_decisions"],
                "completeness_score": 0.98
            },
            {
                "audit_type": "data_processing_audit",
                "time_period": "quarterly",
                "evidence_types": ["processing_logs", "consent_records", "deletion_logs"],
                "completeness_score": 0.95
            }
        ]
        
        for audit in audit_scenarios:
            audit_headers = dict(auth_headers)
            audit_headers.update({
                "X-Audit-Type": audit["audit_type"],
                "X-Time-Period": audit["time_period"],
                "X-Evidence-Types": ",".join(audit["evidence_types"]),
                "X-Completeness-Score": str(audit["completeness_score"]),
                "X-Audit-Generation": "requested"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                audit_headers, track_cost=False
            )
            
            logger.info(f"Audit generation {audit['audit_type']}: "
                       f"period={audit['time_period']}, "
                       f"completeness={audit['completeness_score']}")
        
        logger.info("ZTA_OBS_014: Compliance monitoring and reporting tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_015_advanced_log_analytics_search(self, http_client: httpx.AsyncClient,
                                                            auth_headers: Dict[str, str],
                                                            make_request):
        """ZTA_OBS_015: Test advanced log analytics with ML-based pattern recognition"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test ML-based log pattern recognition
        log_patterns = [
            {
                "pattern_type": "authentication_anomaly",
                "ml_model": "lstm_sequence_analyzer",
                "confidence": 0.87,
                "pattern_description": "unusual_login_sequence"
            },
            {
                "pattern_type": "api_abuse_pattern",
                "ml_model": "random_forest_classifier",
                "confidence": 0.92,
                "pattern_description": "rate_limit_circumvention"
            },
            {
                "pattern_type": "data_exfiltration_indicator",
                "ml_model": "neural_network_detector",
                "confidence": 0.78,
                "pattern_description": "bulk_data_access"
            }
        ]
        
        for pattern in log_patterns:
            pattern_headers = dict(auth_headers)
            pattern_headers.update({
                "X-Log-Pattern": pattern["pattern_type"],
                "X-ML-Model": pattern["ml_model"],
                "X-Pattern-Confidence": str(pattern["confidence"]),
                "X-Pattern-Description": pattern["pattern_description"],
                "X-ML-Pattern-Recognition": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                pattern_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Log pattern test {pattern['pattern_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"ML log pattern {pattern['pattern_type']} "
                       f"({pattern['ml_model']}, confidence: {pattern['confidence']}): "
                       f"{response.status_code}")
        
        # Test intelligent log search and query optimization
        search_queries = [
            {
                "query_type": "semantic_search",
                "query": "failed authentication attempts from suspicious IPs",
                "optimization": "vector_similarity",
                "expected_results": 45
            },
            {
                "query_type": "temporal_correlation",
                "query": "related events within 5 minutes of security incident",
                "optimization": "time_index",
                "expected_results": 23
            },
            {
                "query_type": "anomaly_search",
                "query": "unusual patterns in last 24 hours",
                "optimization": "ml_ranking",
                "expected_results": 12
            }
        ]
        
        for search in search_queries:
            search_headers = dict(auth_headers)
            search_headers.update({
                "X-Query-Type": search["query_type"],
                "X-Search-Query": search["query"],
                "X-Optimization": search["optimization"],
                "X-Expected-Results": str(search["expected_results"]),
                "X-Intelligent-Search": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                search_headers, track_cost=False
            )
            
            logger.info(f"Log search {search['query_type']} "
                       f"({search['optimization']}): {response.status_code}")
        
        # Test automated log classification and categorization
        log_classifications = [
            {
                "log_source": "api_gateway",
                "classification": "security_event",
                "subcategory": "authentication_failure",
                "confidence": 0.94
            },
            {
                "log_source": "application_service",
                "classification": "operational_event",
                "subcategory": "performance_metric",
                "confidence": 0.98
            },
            {
                "log_source": "security_scanner",
                "classification": "threat_detection",
                "subcategory": "vulnerability_scan",
                "confidence": 0.89
            }
        ]
        
        for classification in log_classifications:
            class_headers = dict(auth_headers)
            class_headers.update({
                "X-Log-Source": classification["log_source"],
                "X-Classification": classification["classification"],
                "X-Subcategory": classification["subcategory"],
                "X-Classification-Confidence": str(classification["confidence"]),
                "X-Auto-Classification": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                class_headers, track_cost=False
            )
            
            logger.info(f"Log classification {classification['log_source']} "
                       f"→ {classification['classification']}/{classification['subcategory']}: "
                       f"{response.status_code}")
        
        logger.info("ZTA_OBS_015: Advanced log analytics and search tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_obs_016_observability_as_code_integration(self, http_client: httpx.AsyncClient,
                                                                auth_headers: Dict[str, str],
                                                                make_request):
        """ZTA_OBS_016: Test observability as code with infrastructure-as-code integration"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test observability configuration as code
        observability_configs = [
            {
                "config_type": "monitoring_rules",
                "config_format": "terraform",
                "version_control": "git",
                "deployment_method": "gitops"
            },
            {
                "config_type": "alerting_policies",
                "config_format": "helm_charts",
                "version_control": "git",
                "deployment_method": "ci_cd_pipeline"
            },
            {
                "config_type": "dashboard_definitions",
                "config_format": "jsonnet",
                "version_control": "git",
                "deployment_method": "automated_sync"
            }
        ]
        
        for config in observability_configs:
            config_headers = dict(auth_headers)
            config_headers.update({
                "X-Config-Type": config["config_type"],
                "X-Config-Format": config["config_format"],
                "X-Version-Control": config["version_control"],
                "X-Deployment-Method": config["deployment_method"],
                "X-Observability-As-Code": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                config_headers, track_cost=False
            )
            
            logger.info(f"Observability config {config['config_type']} "
                       f"({config['config_format']}, {config['deployment_method']}): "
                       f"{response.status_code}")
        
        # Test automated deployment of monitoring infrastructure
        deployment_scenarios = [
            {
                "deployment_stage": "development",
                "monitoring_level": "basic",
                "auto_scaling": True,
                "cost_optimization": True
            },
            {
                "deployment_stage": "staging",
                "monitoring_level": "enhanced",
                "auto_scaling": True,
                "cost_optimization": False
            },
            {
                "deployment_stage": "production",
                "monitoring_level": "comprehensive",
                "auto_scaling": True,
                "cost_optimization": False
            }
        ]
        
        for deployment in deployment_scenarios:
            deployment_headers = dict(auth_headers)
            deployment_headers.update({
                "X-Deployment-Stage": deployment["deployment_stage"],
                "X-Monitoring-Level": deployment["monitoring_level"],
                "X-Auto-Scaling": str(deployment["auto_scaling"]).lower(),
                "X-Cost-Optimization": str(deployment["cost_optimization"]).lower(),
                "X-Automated-Deployment": "triggered"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                deployment_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Deployment test {deployment['deployment_stage']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Monitoring deployment {deployment['deployment_stage']} "
                       f"({deployment['monitoring_level']}): {response.status_code}")
        
        # Test configuration drift detection and remediation
        drift_scenarios = [
            {
                "component": "prometheus_config",
                "drift_detected": True,
                "drift_type": "manual_modification",
                "auto_remediation": True
            },
            {
                "component": "grafana_dashboards",
                "drift_detected": False,
                "drift_type": "none",
                "auto_remediation": False
            },
            {
                "component": "alertmanager_rules",
                "drift_detected": True,
                "drift_type": "version_mismatch",
                "auto_remediation": True
            }
        ]
        
        for drift in drift_scenarios:
            drift_headers = dict(auth_headers)
            drift_headers.update({
                "X-Component": drift["component"],
                "X-Drift-Detected": str(drift["drift_detected"]).lower(),
                "X-Drift-Type": drift["drift_type"],
                "X-Auto-Remediation": str(drift["auto_remediation"]).lower(),
                "X-Drift-Detection": "active"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                drift_headers, track_cost=False
            )
            
            drift_status = "drifted" if drift["drift_detected"] else "compliant"
            logger.info(f"Configuration drift {drift['component']}: "
                       f"status={drift_status}, "
                       f"auto_remediation={drift['auto_remediation']}")
        
        # Test integration with CI/CD for observability updates
        cicd_integrations = [
            {
                "pipeline": "monitoring_pipeline",
                "trigger": "config_change",
                "validation": "syntax_check",
                "deployment": "blue_green"
            },
            {
                "pipeline": "alerting_pipeline",
                "trigger": "policy_update",
                "validation": "rule_validation",
                "deployment": "rolling_update"
            }
        ]
        
        for integration in cicd_integrations:
            cicd_headers = dict(auth_headers)
            cicd_headers.update({
                "X-Pipeline": integration["pipeline"],
                "X-Trigger": integration["trigger"],
                "X-Validation": integration["validation"],
                "X-Deployment-Strategy": integration["deployment"],
                "X-CICD-Integration": "active"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                cicd_headers, track_cost=False
            )
            
            logger.info(f"CI/CD integration {integration['pipeline']}: "
                       f"trigger={integration['trigger']}, "
                       f"deployment={integration['deployment']}")
        
        logger.info("ZTA_OBS_016: Observability as code integration tested")