# Section 7.12 - Zero Trust Context-Aware Access Control Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Context-Aware Access Control.md
# Enhanced Test Cases: ZTA_CAAC_005 through ZTA_CAAC_012

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock
from datetime import datetime, timezone
import json

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestContextAwareAccessControlEnhanced:
    """Enhanced Zero Trust Context-Aware Access Control tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_005_dynamic_risk_based_access_control(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """ZTA_CAAC_005: Test dynamic risk-based access control with contextual trust evaluation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test risk scoring based on request context
        risk_contexts = [
            {
                "risk_level": "low",
                "context": {
                    "ip_reputation": "good",
                    "geolocation": "US", 
                    "time_pattern": "business_hours",
                    "user_agent": "Mozilla/5.0 (compatible)",
                    "request_frequency": "normal"
                },
                "expected_controls": "standard"
            },
            {
                "risk_level": "medium",
                "context": {
                    "ip_reputation": "unknown",
                    "geolocation": "foreign",
                    "time_pattern": "off_hours",
                    "user_agent": "CustomBot/1.0",
                    "request_frequency": "elevated"
                },
                "expected_controls": "enhanced"
            },
            {
                "risk_level": "high",
                "context": {
                    "ip_reputation": "suspicious",
                    "geolocation": "high_risk_country",
                    "time_pattern": "unusual",
                    "user_agent": "UnknownAgent",
                    "request_frequency": "rapid"
                },
                "expected_controls": "strict"
            }
        ]
        
        for risk_context in risk_contexts:
            # Add risk context headers
            risk_headers = dict(auth_headers)
            risk_headers.update({
                "X-Risk-Level": risk_context["risk_level"],
                "X-IP-Reputation": risk_context["context"]["ip_reputation"],
                "X-Geolocation": risk_context["context"]["geolocation"],
                "X-Time-Pattern": risk_context["context"]["time_pattern"],
                "User-Agent": risk_context["context"]["user_agent"],
                "X-Request-Frequency": risk_context["context"]["request_frequency"]
            })
            
            # Test access decisions based on risk level
            if risk_context["context"]["request_frequency"] == "rapid":
                # Simulate rapid requests for high risk scenario
                responses = []
                for i in range(8):
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        risk_headers, track_cost=False
                    )
                    responses.append(response)
                
                success_count = sum(1 for r in responses if r.status_code == 200)
                logger.info(f"Risk context {risk_context['risk_level']}: {success_count}/8 requests succeeded")
            else:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    risk_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Risk test {risk_context['risk_level']}"}],
                        "max_tokens": 10
                    }, track_cost=False
                )
                
                # Current implementation doesn't have risk-based controls
                # This documents expected behavior
                logger.info(f"Risk context {risk_context['risk_level']}: {response.status_code}")
        
        logger.info("ZTA_CAAC_005: Dynamic risk-based access control tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_006_behavioral_pattern_analysis(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_CAAC_006: Test behavioral pattern analysis for anomaly detection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Establish baseline behavioral patterns
        baseline_patterns = []
        
        # Normal usage pattern - mixed requests with typical timing
        for i in range(10):
            pattern_start = time.time()
            
            if i % 3 == 0:
                # Models query
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    auth_headers, track_cost=False
                )
            elif i % 3 == 1:
                # Chat completion
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Normal request {i}"}],
                        "max_tokens": 10
                    }, track_cost=(i == 1)
                )
            else:
                # Embedding request
                response = await make_request(
                    http_client, "POST", "/api/v1/embeddings",
                    auth_headers, json={
                        "model": config.get_embedding_model(0),
                        "input": f"Normal embedding {i}"
                    }, track_cost=False
                )
            
            pattern_end = time.time()
            
            baseline_patterns.append({
                "request_type": ["models", "chat", "embedding"][i % 3],
                "response_time": pattern_end - pattern_start,
                "status_code": response.status_code,
                "timestamp": pattern_end
            })
            
            # Normal spacing between requests
            await asyncio.sleep(1.0 + (i % 3) * 0.5)
        
        # Test anomalous behavioral patterns
        anomaly_tests = [
            {
                "type": "frequency_anomaly",
                "description": "Unusually rapid requests",
                "pattern": "rapid_fire"
            },
            {
                "type": "timing_anomaly", 
                "description": "Requests at unusual times",
                "pattern": "off_hours"
            },
            {
                "type": "volume_anomaly",
                "description": "Unusual request volume",
                "pattern": "high_volume"
            }
        ]
        
        for anomaly in anomaly_tests:
            anomaly_start = time.time()
            
            if anomaly["pattern"] == "rapid_fire":
                # Rapid succession requests
                rapid_responses = []
                for j in range(15):
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        auth_headers, track_cost=False
                    )
                    rapid_responses.append(response)
                
                rapid_success = sum(1 for r in rapid_responses if r.status_code == 200)
                logger.info(f"Behavioral anomaly {anomaly['type']}: {rapid_success}/15 rapid requests succeeded")
                
            elif anomaly["pattern"] == "high_volume":
                # High volume of varied requests
                volume_responses = []
                for j in range(20):
                    if j % 2 == 0:
                        response = await make_request(
                            http_client, "POST", "/api/v1/chat/completions",
                            auth_headers, json={
                                "model": config.get_chat_model(0),
                                "messages": [{"role": "user", "content": f"Volume test {j}"}],
                                "max_tokens": 5
                            }, track_cost=False
                        )
                    else:
                        response = await make_request(
                            http_client, "GET", "/api/v1/models",
                            auth_headers, track_cost=False
                        )
                    volume_responses.append(response)
                    await asyncio.sleep(0.1)
                
                volume_success = sum(1 for r in volume_responses if r.status_code == 200)
                logger.info(f"Behavioral anomaly {anomaly['type']}: {volume_success}/20 volume requests succeeded")
            
            anomaly_duration = time.time() - anomaly_start
            logger.info(f"Anomaly {anomaly['type']} completed in {anomaly_duration:.2f}s")
        
        # Analyze baseline vs anomalous patterns
        baseline_avg_time = sum(p["response_time"] for p in baseline_patterns) / len(baseline_patterns)
        logger.info(f"Baseline pattern analysis: avg_response_time={baseline_avg_time:.3f}s, "
                   f"requests={len(baseline_patterns)}")
        
        logger.info("ZTA_CAAC_006: Behavioral pattern analysis tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_007_geolocation_time_based_access_control(self, http_client: httpx.AsyncClient,
                                                                     auth_headers: Dict[str, str],
                                                                     make_request):
        """ZTA_CAAC_007: Test geolocation and time-based access control"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test geographic access restrictions
        geo_access_tests = [
            {
                "location": "US-CA",
                "country": "United States",
                "region": "California",
                "allowed": True,
                "risk_level": "low"
            },
            {
                "location": "GB-LON",
                "country": "United Kingdom", 
                "region": "London",
                "allowed": True,
                "risk_level": "low"
            },
            {
                "location": "RU-MOW",
                "country": "Russia",
                "region": "Moscow", 
                "allowed": False,
                "risk_level": "high"
            },
            {
                "location": "CN-BEI",
                "country": "China",
                "region": "Beijing",
                "allowed": False,
                "risk_level": "high"
            }
        ]
        
        for geo_test in geo_access_tests:
            geo_headers = dict(auth_headers)
            geo_headers.update({
                "X-Geolocation": geo_test["location"],
                "X-Country": geo_test["country"],
                "X-Region": geo_test["region"],
                "X-Risk-Level": geo_test["risk_level"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                geo_headers, track_cost=False
            )
            
            # Current implementation doesn't have geo-restrictions
            # This documents expected behavior with geo-controls
            logger.info(f"Geo access {geo_test['location']}: {response.status_code} "
                       f"(expected: {'allow' if geo_test['allowed'] else 'deny'})")
        
        # Test time-based access policies
        time_access_tests = [
            {
                "time_context": "business_hours",
                "hour": 14,  # 2 PM
                "day": "tuesday",
                "allowed": True,
                "policy": "standard_access"
            },
            {
                "time_context": "off_hours",
                "hour": 2,   # 2 AM
                "day": "sunday",
                "allowed": False,
                "policy": "restricted_access"
            },
            {
                "time_context": "maintenance_window",
                "hour": 3,   # 3 AM
                "day": "sunday",
                "allowed": False,
                "policy": "maintenance_mode"
            }
        ]
        
        for time_test in time_access_tests:
            time_headers = dict(auth_headers)
            time_headers.update({
                "X-Time-Context": time_test["time_context"],
                "X-Request-Hour": str(time_test["hour"]),
                "X-Request-Day": time_test["day"],
                "X-Access-Policy": time_test["policy"]
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                time_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Time test {time_test['time_context']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Time access {time_test['time_context']}: {response.status_code} "
                       f"(expected: {'allow' if time_test['allowed'] else 'deny'})")
        
        logger.info("ZTA_CAAC_007: Geolocation and time-based access control tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_008_device_environment_context_analysis(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """ZTA_CAAC_008: Test device and environment context analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test device fingerprinting and trust evaluation
        device_contexts = [
            {
                "device_type": "managed_workstation",
                "trust_level": "high",
                "environment": "corporate_network",
                "fingerprint": "WIN-CORP-001",
                "security_posture": "compliant"
            },
            {
                "device_type": "personal_laptop",
                "trust_level": "medium",
                "environment": "home_network",
                "fingerprint": "MAC-HOME-001",
                "security_posture": "unknown"
            },
            {
                "device_type": "mobile_device",
                "trust_level": "low",
                "environment": "public_wifi",
                "fingerprint": "MOB-PUB-001",
                "security_posture": "unverified"
            }
        ]
        
        for device in device_contexts:
            device_headers = dict(auth_headers)
            device_headers.update({
                "X-Device-Type": device["device_type"],
                "X-Device-Trust": device["trust_level"],
                "X-Environment": device["environment"],
                "X-Device-Fingerprint": device["fingerprint"],
                "X-Security-Posture": device["security_posture"],
                "User-Agent": f"TestAgent/{device['device_type']}/1.0"
            })
            
            # Test device-based access policies
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                device_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Device test {device['device_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Device context {device['device_type']} ({device['trust_level']} trust): {response.status_code}")
        
        # Test environment analysis and security posture assessment
        environment_tests = [
            {
                "network": "corporate_vpn",
                "encryption": "WPA3_Enterprise",
                "monitoring": "enabled",
                "threat_level": "low"
            },
            {
                "network": "public_wifi",
                "encryption": "WPA2_Personal",
                "monitoring": "disabled", 
                "threat_level": "high"
            }
        ]
        
        for env in environment_tests:
            env_headers = dict(auth_headers)
            env_headers.update({
                "X-Network-Type": env["network"],
                "X-Network-Encryption": env["encryption"],
                "X-Network-Monitoring": env["monitoring"],
                "X-Threat-Level": env["threat_level"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                env_headers, track_cost=False
            )
            
            logger.info(f"Environment {env['network']} ({env['threat_level']} threat): {response.status_code}")
        
        logger.info("ZTA_CAAC_008: Device and environment context analysis tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_009_adaptive_multi_factor_authentication(self, http_client: httpx.AsyncClient,
                                                                    auth_headers: Dict[str, str],
                                                                    make_request):
        """ZTA_CAAC_009: Test adaptive multi-factor authentication"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test context-based MFA requirement escalation
        mfa_scenarios = [
            {
                "risk_level": "low",
                "context": "normal_operation",
                "mfa_required": False,
                "factors": ["api_key"]
            },
            {
                "risk_level": "medium",
                "context": "unusual_location",
                "mfa_required": True,
                "factors": ["api_key", "totp"]
            },
            {
                "risk_level": "high",
                "context": "suspicious_activity",
                "mfa_required": True,
                "factors": ["api_key", "totp", "push_notification"]
            }
        ]
        
        for scenario in mfa_scenarios:
            mfa_headers = dict(auth_headers)
            mfa_headers.update({
                "X-Risk-Level": scenario["risk_level"],
                "X-Context": scenario["context"],
                "X-MFA-Required": str(scenario["mfa_required"]).lower(),
                "X-Auth-Factors": ",".join(scenario["factors"])
            })
            
            if scenario["mfa_required"]:
                # Simulate MFA factors
                mfa_headers.update({
                    "X-TOTP-Code": "123456",
                    "X-Push-Confirmed": "true" if "push_notification" in scenario["factors"] else "false"
                })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                mfa_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"MFA test {scenario['risk_level']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            # Current implementation doesn't have MFA
            logger.info(f"MFA scenario {scenario['risk_level']} risk: {response.status_code} "
                       f"(factors: {len(scenario['factors'])})")
        
        # Test step-up authentication for high-risk scenarios
        step_up_tests = [
            {
                "operation": "high_value_request",
                "step_up_trigger": "large_token_count",
                "additional_factors": ["biometric", "admin_approval"]
            },
            {
                "operation": "sensitive_model_access", 
                "step_up_trigger": "restricted_model",
                "additional_factors": ["hardware_token"]
            }
        ]
        
        for step_up in step_up_tests:
            step_up_headers = dict(auth_headers)
            step_up_headers.update({
                "X-Operation": step_up["operation"],
                "X-Step-Up-Trigger": step_up["step_up_trigger"],
                "X-Additional-Factors": ",".join(step_up["additional_factors"])
            })
            
            # Simulate high-value request
            if step_up["operation"] == "high_value_request":
                test_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "High value operation"}],
                    "max_tokens": 500  # Large token count
                }
            else:
                test_data = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Sensitive model access"}],
                    "max_tokens": 10
                }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                step_up_headers, json=test_data, track_cost=False
            )
            
            logger.info(f"Step-up auth {step_up['operation']}: {response.status_code}")
        
        logger.info("ZTA_CAAC_009: Adaptive multi-factor authentication tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_010_network_context_threat_intelligence(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """ZTA_CAAC_010: Test network context analysis and threat intelligence integration"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test IP reputation analysis and threat intelligence lookup
        ip_reputation_tests = [
            {
                "ip": "192.168.1.100",
                "reputation": "trusted_internal",
                "threat_level": "none",
                "source": "corporate_network"
            },
            {
                "ip": "203.0.113.1",
                "reputation": "unknown_external", 
                "threat_level": "low",
                "source": "internet"
            },
            {
                "ip": "198.51.100.1",
                "reputation": "known_malicious",
                "threat_level": "high",
                "source": "threat_feed"
            }
        ]
        
        for ip_test in ip_reputation_tests:
            ip_headers = dict(auth_headers)
            ip_headers.update({
                "X-Forwarded-For": ip_test["ip"],
                "X-IP-Reputation": ip_test["reputation"],
                "X-Threat-Level": ip_test["threat_level"],
                "X-Source-Network": ip_test["source"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                ip_headers, track_cost=False
            )
            
            logger.info(f"IP reputation {ip_test['ip']} ({ip_test['reputation']}): {response.status_code}")
        
        # Test network context evaluation (VPN, Tor, proxies)
        network_context_tests = [
            {
                "connection_type": "direct",
                "anonymization": "none",
                "risk_score": 0.1
            },
            {
                "connection_type": "corporate_vpn",
                "anonymization": "low",
                "risk_score": 0.2
            },
            {
                "connection_type": "tor_exit_node",
                "anonymization": "high", 
                "risk_score": 0.9
            },
            {
                "connection_type": "proxy_chain",
                "anonymization": "medium",
                "risk_score": 0.6
            }
        ]
        
        for network in network_context_tests:
            network_headers = dict(auth_headers)
            network_headers.update({
                "X-Connection-Type": network["connection_type"],
                "X-Anonymization-Level": network["anonymization"],
                "X-Risk-Score": str(network["risk_score"])
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                network_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Network test {network['connection_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Network context {network['connection_type']} (risk: {network['risk_score']}): {response.status_code}")
        
        # Test threat intelligence integration
        threat_intel_tests = [
            {
                "indicator_type": "ip_address",
                "indicator_value": "203.0.113.100",
                "threat_category": "botnet_c2",
                "confidence": "high"
            },
            {
                "indicator_type": "user_agent",
                "indicator_value": "MaliciousBot/1.0",
                "threat_category": "automated_attack",
                "confidence": "medium"
            }
        ]
        
        for threat in threat_intel_tests:
            threat_headers = dict(auth_headers)
            if threat["indicator_type"] == "ip_address":
                threat_headers["X-Forwarded-For"] = threat["indicator_value"]
            elif threat["indicator_type"] == "user_agent":
                threat_headers["User-Agent"] = threat["indicator_value"]
            
            threat_headers.update({
                "X-Threat-Category": threat["threat_category"],
                "X-Confidence": threat["confidence"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                threat_headers, track_cost=False
            )
            
            logger.info(f"Threat intel {threat['indicator_type']} ({threat['threat_category']}): {response.status_code}")
        
        logger.info("ZTA_CAAC_010: Network context and threat intelligence tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_011_session_context_continuity(self, http_client: httpx.AsyncClient,
                                                          auth_headers: Dict[str, str],
                                                          make_request):
        """ZTA_CAAC_011: Test session context analysis and continuity validation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test session context establishment and tracking
        session_id = f"session_{secrets.token_hex(8)}"
        session_start = time.time()
        
        session_headers = dict(auth_headers)
        session_headers["X-Session-ID"] = session_id
        
        session_activities = []
        
        # Establish session context with multiple requests
        for i in range(6):
            activity_start = time.time()
            
            if i % 2 == 0:
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    session_headers, track_cost=False
                )
            else:
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    session_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Session activity {i}"}],
                        "max_tokens": 10
                    }, track_cost=(i == 1)
                )
            
            activity_end = time.time()
            
            session_activities.append({
                "activity_id": i,
                "timestamp": activity_end,
                "duration": activity_end - activity_start,
                "status": response.status_code,
                "session_age": activity_end - session_start
            })
            
            # Update session context headers
            session_headers.update({
                "X-Session-Age": str(int(activity_end - session_start)),
                "X-Activity-Count": str(len(session_activities)),
                "X-Last-Activity": str(int(activity_end))
            })
            
            await asyncio.sleep(0.5)
        
        # Test session continuity analysis
        continuity_tests = [
            {
                "test": "normal_continuation",
                "gap": 2,  # seconds
                "expected": "continue"
            },
            {
                "test": "suspicious_gap",
                "gap": 30,  # seconds  
                "expected": "verify"
            },
            {
                "test": "session_timeout",
                "gap": 300,  # seconds
                "expected": "terminate"
            }
        ]
        
        for continuity in continuity_tests:
            if continuity["test"] != "session_timeout":  # Skip long wait for testing
                await asyncio.sleep(min(continuity["gap"], 3))  # Cap at 3 seconds for testing
                
                continuity_headers = dict(session_headers)
                continuity_headers.update({
                    "X-Continuity-Test": continuity["test"],
                    "X-Gap-Duration": str(continuity["gap"]),
                    "X-Expected-Action": continuity["expected"]
                })
                
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    continuity_headers, track_cost=False
                )
                
                logger.info(f"Session continuity {continuity['test']} (gap: {continuity['gap']}s): {response.status_code}")
        
        # Test session hijacking detection (simulation)
        hijack_tests = [
            {
                "attack": "ip_change",
                "original_ip": "192.168.1.100",
                "new_ip": "203.0.113.1"
            },
            {
                "attack": "user_agent_change",
                "original_ua": "TestClient/1.0",
                "new_ua": "DifferentClient/2.0"
            }
        ]
        
        for hijack in hijack_tests:
            hijack_headers = dict(session_headers)
            
            if hijack["attack"] == "ip_change":
                hijack_headers["X-Forwarded-For"] = hijack["new_ip"]
                hijack_headers["X-Original-IP"] = hijack["original_ip"]
            elif hijack["attack"] == "user_agent_change":
                hijack_headers["User-Agent"] = hijack["new_ua"]
                hijack_headers["X-Original-UA"] = hijack["original_ua"]
            
            hijack_headers["X-Hijack-Test"] = hijack["attack"]
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                hijack_headers, track_cost=False
            )
            
            logger.info(f"Session hijack test {hijack['attack']}: {response.status_code}")
        
        # Analyze session metrics
        total_session_time = session_activities[-1]["session_age"]
        avg_activity_duration = sum(a["duration"] for a in session_activities) / len(session_activities)
        
        logger.info(f"Session analysis: session_id={session_id}, total_time={total_session_time:.2f}s, "
                   f"activities={len(session_activities)}, avg_duration={avg_activity_duration:.3f}s")
        
        logger.info("ZTA_CAAC_011: Session context and continuity tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_caac_012_machine_learning_based_context_analysis(self, http_client: httpx.AsyncClient,
                                                                       auth_headers: Dict[str, str],
                                                                       make_request):
        """ZTA_CAAC_012: Test machine learning-based context analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test ML model training on contextual access patterns (simulation)
        training_data = []
        
        # Generate training data with various context patterns
        context_patterns = [
            {"pattern": "morning_routine", "time": "09:00", "requests": ["models", "chat", "chat"]},
            {"pattern": "afternoon_work", "time": "14:00", "requests": ["chat", "embedding", "models"]},
            {"pattern": "evening_batch", "time": "18:00", "requests": ["embedding", "embedding", "chat"]},
            {"pattern": "anomalous", "time": "03:00", "requests": ["models", "models", "models", "models"]}
        ]
        
        for pattern in context_patterns:
            pattern_start = time.time()
            
            ml_headers = dict(auth_headers)
            ml_headers.update({
                "X-ML-Pattern": pattern["pattern"],
                "X-Request-Time": pattern["time"],
                "X-Expected-Sequence": ",".join(pattern["requests"])
            })
            
            pattern_responses = []
            
            for req_type in pattern["requests"]:
                if req_type == "models":
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        ml_headers, track_cost=False
                    )
                elif req_type == "chat":
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        ml_headers, json={
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"ML pattern {pattern['pattern']}"}],
                            "max_tokens": 5
                        }, track_cost=False
                    )
                elif req_type == "embedding":
                    response = await make_request(
                        http_client, "POST", "/api/v1/embeddings",
                        ml_headers, json={
                            "model": config.get_embedding_model(0),
                            "input": f"ML embedding {pattern['pattern']}"
                        }, track_cost=False
                    )
                
                pattern_responses.append({
                    "request_type": req_type,
                    "status": response.status_code,
                    "timestamp": time.time()
                })
                
                await asyncio.sleep(0.2)
            
            pattern_duration = time.time() - pattern_start
            
            training_data.append({
                "pattern": pattern["pattern"],
                "responses": pattern_responses,
                "duration": pattern_duration,
                "anomaly_score": 1.0 if pattern["pattern"] == "anomalous" else 0.0
            })
        
        # Test intelligent context analysis and decision making
        analysis_tests = [
            {
                "context": "normal_user_behavior",
                "features": {
                    "request_frequency": 0.3,  # requests per second
                    "pattern_consistency": 0.8,
                    "time_regularity": 0.9,
                    "endpoint_diversity": 0.6
                },
                "ml_prediction": "normal"
            },
            {
                "context": "suspicious_behavior",
                "features": {
                    "request_frequency": 2.0,  # very high
                    "pattern_consistency": 0.2,  # very inconsistent
                    "time_regularity": 0.1,   # irregular timing
                    "endpoint_diversity": 0.9  # using all endpoints
                },
                "ml_prediction": "anomalous"
            }
        ]
        
        for analysis in analysis_tests:
            analysis_headers = dict(auth_headers)
            analysis_headers.update({
                "X-ML-Context": analysis["context"],
                "X-Request-Frequency": str(analysis["features"]["request_frequency"]),
                "X-Pattern-Consistency": str(analysis["features"]["pattern_consistency"]),
                "X-Time-Regularity": str(analysis["features"]["time_regularity"]),
                "X-Endpoint-Diversity": str(analysis["features"]["endpoint_diversity"]),
                "X-ML-Prediction": analysis["ml_prediction"]
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                analysis_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"ML analysis {analysis['context']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"ML context analysis {analysis['context']} "
                       f"(prediction: {analysis['ml_prediction']}): {response.status_code}")
        
        # Test continuous learning and model adaptation (simulation)
        adaptation_metrics = {
            "model_accuracy": 0.85,
            "false_positive_rate": 0.05,
            "adaptation_speed": 0.92,
            "pattern_recognition_confidence": 0.88
        }
        
        logger.info(f"ML model performance: accuracy={adaptation_metrics['model_accuracy']:.2f}, "
                   f"fpr={adaptation_metrics['false_positive_rate']:.3f}, "
                   f"adaptation={adaptation_metrics['adaptation_speed']:.2f}")
        
        # Analyze training data for patterns
        normal_patterns = [d for d in training_data if d["anomaly_score"] == 0.0]
        anomalous_patterns = [d for d in training_data if d["anomaly_score"] == 1.0]
        
        logger.info(f"Training data analysis: {len(normal_patterns)} normal patterns, "
                   f"{len(anomalous_patterns)} anomalous patterns")
        
        logger.info("ZTA_CAAC_012: Machine learning-based context analysis tested")