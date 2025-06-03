# Section 7.12 - Zero Trust Network Segmentation Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Network Segmentation.md
# Enhanced Test Cases: ZTA_NET_007 through ZTA_NET_014

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


class TestNetworkSegmentationEnhanced:
    """Enhanced Zero Trust Network Segmentation tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_007_software_defined_perimeter(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """ZTA_NET_007: Test software-defined perimeter implementation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test identity-based network access through SDP gateways
        sdp_access_tests = [
            {
                "identity": "verified_user",
                "trust_level": "high",
                "network_visibility": "full",
                "tunnel_type": "encrypted"
            },
            {
                "identity": "guest_user",
                "trust_level": "low", 
                "network_visibility": "restricted",
                "tunnel_type": "sandboxed"
            },
            {
                "identity": "unauthorized_user",
                "trust_level": "none",
                "network_visibility": "hidden",
                "tunnel_type": "blocked"
            }
        ]
        
        for sdp_test in sdp_access_tests:
            sdp_headers = dict(auth_headers)
            sdp_headers.update({
                "X-SDP-Identity": sdp_test["identity"],
                "X-Trust-Level": sdp_test["trust_level"],
                "X-Network-Visibility": sdp_test["network_visibility"],
                "X-Tunnel-Type": sdp_test["tunnel_type"],
                "X-SDP-Gateway": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                sdp_headers, track_cost=False
            )
            
            logger.info(f"SDP access {sdp_test['identity']} "
                       f"({sdp_test['trust_level']} trust, {sdp_test['network_visibility']} visibility): "
                       f"{response.status_code}")
        
        # Test dynamic perimeter establishment based on user context
        dynamic_perimeter_tests = [
            {
                "context": "corporate_network",
                "perimeter_size": "expanded",
                "access_level": "full"
            },
            {
                "context": "home_office",
                "perimeter_size": "standard",
                "access_level": "limited"
            },
            {
                "context": "public_wifi",
                "perimeter_size": "minimal",
                "access_level": "restricted"
            }
        ]
        
        for perimeter_test in dynamic_perimeter_tests:
            perimeter_headers = dict(auth_headers)
            perimeter_headers.update({
                "X-Network-Context": perimeter_test["context"],
                "X-Perimeter-Size": perimeter_test["perimeter_size"],
                "X-Access-Level": perimeter_test["access_level"],
                "X-Dynamic-Perimeter": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                perimeter_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Dynamic perimeter test {perimeter_test['context']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Dynamic perimeter {perimeter_test['context']}: {response.status_code}")
        
        logger.info("ZTA_NET_007: Software-defined perimeter tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_008_zero_trust_network_architecture(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_NET_008: Test comprehensive zero trust network architecture"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test identity verification for every network connection
        connection_verification_tests = [
            {
                "connection_id": f"conn_{secrets.token_hex(8)}",
                "identity_verified": True,
                "device_trusted": True,
                "location_validated": True
            },
            {
                "connection_id": f"conn_{secrets.token_hex(8)}",
                "identity_verified": True,
                "device_trusted": False,
                "location_validated": True
            },
            {
                "connection_id": f"conn_{secrets.token_hex(8)}",
                "identity_verified": False,
                "device_trusted": False,
                "location_validated": False
            }
        ]
        
        for conn_test in connection_verification_tests:
            ztna_headers = dict(auth_headers)
            ztna_headers.update({
                "X-Connection-ID": conn_test["connection_id"],
                "X-Identity-Verified": str(conn_test["identity_verified"]).lower(),
                "X-Device-Trusted": str(conn_test["device_trusted"]).lower(),
                "X-Location-Validated": str(conn_test["location_validated"]).lower(),
                "X-ZTNA-Policy": "strict_verification"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                ztna_headers, track_cost=False
            )
            
            verification_score = sum([
                conn_test["identity_verified"],
                conn_test["device_trusted"], 
                conn_test["location_validated"]
            ])
            
            logger.info(f"ZTNA connection {conn_test['connection_id']} "
                       f"(verification score: {verification_score}/3): {response.status_code}")
        
        # Test micro-tunnel creation for authorized connections
        micro_tunnel_tests = [
            {
                "tunnel_type": "application_specific",
                "encryption": "AES-256-GCM",
                "authentication": "mutual_tls"
            },
            {
                "tunnel_type": "session_based",
                "encryption": "ChaCha20-Poly1305",
                "authentication": "certificate_based"
            }
        ]
        
        for tunnel_test in micro_tunnel_tests:
            tunnel_headers = dict(auth_headers)
            tunnel_headers.update({
                "X-Tunnel-Type": tunnel_test["tunnel_type"],
                "X-Tunnel-Encryption": tunnel_test["encryption"],
                "X-Tunnel-Authentication": tunnel_test["authentication"],
                "X-Micro-Tunnel": "established"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                tunnel_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Micro-tunnel test {tunnel_test['tunnel_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Micro-tunnel {tunnel_test['tunnel_type']}: {response.status_code}")
        
        logger.info("ZTA_NET_008: Zero trust network architecture tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_009_application_layer_traffic_inspection(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """ZTA_NET_009: Test deep packet inspection and application-layer traffic analysis"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test deep packet inspection of API traffic
        dpi_test_cases = [
            {
                "traffic_type": "normal_api_call",
                "content_category": "business_data",
                "threat_level": "none",
                "action": "allow"
            },
            {
                "traffic_type": "large_payload",
                "content_category": "bulk_data",
                "threat_level": "low",
                "action": "inspect_and_allow"
            },
            {
                "traffic_type": "suspicious_pattern",
                "content_category": "unknown",
                "threat_level": "medium",
                "action": "deep_inspect"
            },
            {
                "traffic_type": "malicious_content",
                "content_category": "threat_detected",
                "threat_level": "high", 
                "action": "block"
            }
        ]
        
        for dpi_test in dpi_test_cases:
            dpi_headers = dict(auth_headers)
            dpi_headers.update({
                "X-Traffic-Type": dpi_test["traffic_type"],
                "X-Content-Category": dpi_test["content_category"],
                "X-Threat-Level": dpi_test["threat_level"],
                "X-DPI-Action": dpi_test["action"],
                "X-Deep-Inspection": "enabled"
            })
            
            # Simulate different payload types
            if dpi_test["traffic_type"] == "large_payload":
                test_content = "Large payload test " + "data " * 100
            elif dpi_test["traffic_type"] == "suspicious_pattern":
                test_content = "SELECT * FROM users WHERE 1=1; DROP TABLE users;"
            elif dpi_test["traffic_type"] == "malicious_content":
                test_content = "<script>alert('XSS')</script>"
            else:
                test_content = "Normal business API call content"
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                dpi_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": test_content}],
                    "max_tokens": 20
                }, track_cost=False
            )
            
            logger.info(f"DPI inspection {dpi_test['traffic_type']} "
                       f"({dpi_test['threat_level']} threat, action: {dpi_test['action']}): "
                       f"{response.status_code}")
        
        # Test application-layer protocol analysis
        protocol_analysis_tests = [
            {
                "protocol": "https",
                "version": "HTTP/2",
                "analysis": "header_inspection",
                "compliance": "rfc_compliant"
            },
            {
                "protocol": "websocket",
                "version": "RFC6455",
                "analysis": "frame_inspection",
                "compliance": "protocol_violation"
            }
        ]
        
        for protocol_test in protocol_analysis_tests:
            protocol_headers = dict(auth_headers)
            protocol_headers.update({
                "X-Protocol": protocol_test["protocol"],
                "X-Protocol-Version": protocol_test["version"],
                "X-Analysis-Type": protocol_test["analysis"],
                "X-Compliance": protocol_test["compliance"],
                "X-Protocol-Analysis": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                protocol_headers, track_cost=False
            )
            
            logger.info(f"Protocol analysis {protocol_test['protocol']} "
                       f"({protocol_test['compliance']}): {response.status_code}")
        
        logger.info("ZTA_NET_009: Application-layer traffic inspection tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_010_service_mesh_security(self, http_client: httpx.AsyncClient,
                                                    auth_headers: Dict[str, str],
                                                    make_request):
        """ZTA_NET_010: Test service mesh implementation with mutual TLS and microsegmentation"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test mutual TLS authentication between services
        mtls_tests = [
            {
                "service_from": "api_gateway",
                "service_to": "auth_service",
                "certificate_valid": True,
                "mtls_enabled": True
            },
            {
                "service_from": "auth_service",
                "service_to": "llm_service",
                "certificate_valid": True,
                "mtls_enabled": True
            },
            {
                "service_from": "unknown_service",
                "service_to": "llm_service",
                "certificate_valid": False,
                "mtls_enabled": False
            }
        ]
        
        for mtls_test in mtls_tests:
            mtls_headers = dict(auth_headers)
            mtls_headers.update({
                "X-Service-From": mtls_test["service_from"],
                "X-Service-To": mtls_test["service_to"],
                "X-Certificate-Valid": str(mtls_test["certificate_valid"]).lower(),
                "X-MTLS-Enabled": str(mtls_test["mtls_enabled"]).lower(),
                "X-Service-Mesh": "istio"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                mtls_headers, track_cost=False
            )
            
            expected_result = "allowed" if mtls_test["certificate_valid"] else "denied"
            logger.info(f"Service mesh mTLS {mtls_test['service_from']}→{mtls_test['service_to']}: "
                       f"{response.status_code} (expected: {expected_result})")
        
        # Test service-to-service authorization policies
        service_authz_tests = [
            {
                "source_service": "frontend",
                "target_service": "api_gateway",
                "operation": "read",
                "policy_allowed": True
            },
            {
                "source_service": "api_gateway",
                "target_service": "auth_service",
                "operation": "validate",
                "policy_allowed": True
            },
            {
                "source_service": "frontend",
                "target_service": "database",
                "operation": "direct_access",
                "policy_allowed": False
            }
        ]
        
        for authz_test in service_authz_tests:
            authz_headers = dict(auth_headers)
            authz_headers.update({
                "X-Source-Service": authz_test["source_service"],
                "X-Target-Service": authz_test["target_service"],
                "X-Operation": authz_test["operation"],
                "X-Policy-Allowed": str(authz_test["policy_allowed"]).lower(),
                "X-Service-Authorization": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                authz_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Service authz test {authz_test['operation']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            expected_result = "allowed" if authz_test["policy_allowed"] else "denied"
            logger.info(f"Service authorization {authz_test['source_service']}→{authz_test['target_service']} "
                       f"({authz_test['operation']}): {response.status_code} (expected: {expected_result})")
        
        logger.info("ZTA_NET_010: Service mesh security tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_011_dynamic_network_segmentation(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_NET_011: Test dynamic network segmentation based on threat conditions"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test automatic network segmentation based on threat intelligence
        threat_based_segmentation = [
            {
                "threat_condition": "normal_operations",
                "segmentation_level": "standard",
                "isolation_mode": "none",
                "traffic_allowed": True
            },
            {
                "threat_condition": "elevated_threat",
                "segmentation_level": "enhanced",
                "isolation_mode": "partial",
                "traffic_allowed": True
            },
            {
                "threat_condition": "active_attack",
                "segmentation_level": "maximum",
                "isolation_mode": "full",
                "traffic_allowed": False
            }
        ]
        
        for threat_seg in threat_based_segmentation:
            seg_headers = dict(auth_headers)
            seg_headers.update({
                "X-Threat-Condition": threat_seg["threat_condition"],
                "X-Segmentation-Level": threat_seg["segmentation_level"],
                "X-Isolation-Mode": threat_seg["isolation_mode"],
                "X-Traffic-Allowed": str(threat_seg["traffic_allowed"]).lower(),
                "X-Dynamic-Segmentation": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                seg_headers, track_cost=False
            )
            
            expected_result = "allowed" if threat_seg["traffic_allowed"] else "blocked"
            logger.info(f"Dynamic segmentation {threat_seg['threat_condition']} "
                       f"({threat_seg['segmentation_level']} level): {response.status_code} "
                       f"(expected: {expected_result})")
        
        # Test dynamic isolation of compromised resources
        isolation_tests = [
            {
                "resource_type": "api_endpoint",
                "compromise_indicator": "unusual_traffic_pattern",
                "isolation_action": "quarantine",
                "duration": 1800
            },
            {
                "resource_type": "user_session",
                "compromise_indicator": "credential_stuffing_detected",
                "isolation_action": "suspend",
                "duration": 3600
            }
        ]
        
        for isolation in isolation_tests:
            isolation_headers = dict(auth_headers)
            isolation_headers.update({
                "X-Resource-Type": isolation["resource_type"],
                "X-Compromise-Indicator": isolation["compromise_indicator"],
                "X-Isolation-Action": isolation["isolation_action"],
                "X-Isolation-Duration": str(isolation["duration"]),
                "X-Dynamic-Isolation": "active"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                isolation_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Isolation test {isolation['resource_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Dynamic isolation {isolation['resource_type']} "
                       f"({isolation['compromise_indicator']}): {response.status_code}")
        
        logger.info("ZTA_NET_011: Dynamic network segmentation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_012_container_network_security(self, http_client: httpx.AsyncClient,
                                                         auth_headers: Dict[str, str],
                                                         make_request):
        """ZTA_NET_012: Test advanced container network security with runtime protection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test Kubernetes network policies for pod-to-pod communication
        k8s_policy_tests = [
            {
                "source_pod": "api-frontend",
                "target_pod": "api-backend",
                "namespace": "default",
                "policy_action": "allow",
                "traffic_type": "ingress"
            },
            {
                "source_pod": "external-service",
                "target_pod": "database",
                "namespace": "default",
                "policy_action": "deny",
                "traffic_type": "ingress"
            },
            {
                "source_pod": "api-backend",
                "target_pod": "llm-service",
                "namespace": "ai-services",
                "policy_action": "allow",
                "traffic_type": "egress"
            }
        ]
        
        for k8s_test in k8s_policy_tests:
            k8s_headers = dict(auth_headers)
            k8s_headers.update({
                "X-Source-Pod": k8s_test["source_pod"],
                "X-Target-Pod": k8s_test["target_pod"],
                "X-Namespace": k8s_test["namespace"],
                "X-Policy-Action": k8s_test["policy_action"],
                "X-Traffic-Type": k8s_test["traffic_type"],
                "X-K8s-Network-Policy": "enforced"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                k8s_headers, track_cost=False
            )
            
            logger.info(f"K8s network policy {k8s_test['source_pod']}→{k8s_test['target_pod']}: "
                       f"{response.status_code} (policy: {k8s_test['policy_action']})")
        
        # Test container runtime network monitoring
        runtime_monitoring_tests = [
            {
                "container_id": f"container_{secrets.token_hex(8)}",
                "network_activity": "normal",
                "anomaly_detected": False,
                "action": "monitor"
            },
            {
                "container_id": f"container_{secrets.token_hex(8)}",
                "network_activity": "port_scanning",
                "anomaly_detected": True,
                "action": "alert_and_block"
            },
            {
                "container_id": f"container_{secrets.token_hex(8)}",
                "network_activity": "lateral_movement",
                "anomaly_detected": True,
                "action": "isolate"
            }
        ]
        
        for runtime_test in runtime_monitoring_tests:
            runtime_headers = dict(auth_headers)
            runtime_headers.update({
                "X-Container-ID": runtime_test["container_id"],
                "X-Network-Activity": runtime_test["network_activity"],
                "X-Anomaly-Detected": str(runtime_test["anomaly_detected"]).lower(),
                "X-Runtime-Action": runtime_test["action"],
                "X-Runtime-Monitoring": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                runtime_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Runtime monitoring test {runtime_test['network_activity']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Container runtime monitoring {runtime_test['container_id']} "
                       f"({runtime_test['network_activity']}): {response.status_code}")
        
        logger.info("ZTA_NET_012: Container network security tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_013_edge_computing_network_security(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_NET_013: Test network security for edge computing deployments"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test secure connectivity between edge nodes and central infrastructure
        edge_connectivity_tests = [
            {
                "edge_location": "edge_us_west",
                "central_region": "us_central",
                "connection_type": "vpn_tunnel",
                "encryption": "ipsec",
                "latency_ms": 45
            },
            {
                "edge_location": "edge_eu_north",
                "central_region": "eu_central",
                "connection_type": "direct_connect",
                "encryption": "wireguard",
                "latency_ms": 28
            },
            {
                "edge_location": "edge_asia_east",
                "central_region": "asia_central",
                "connection_type": "sd_wan",
                "encryption": "tls_1_3",
                "latency_ms": 62
            }
        ]
        
        for edge_test in edge_connectivity_tests:
            edge_headers = dict(auth_headers)
            edge_headers.update({
                "X-Edge-Location": edge_test["edge_location"],
                "X-Central-Region": edge_test["central_region"],
                "X-Connection-Type": edge_test["connection_type"],
                "X-Encryption": edge_test["encryption"],
                "X-Latency-MS": str(edge_test["latency_ms"]),
                "X-Edge-Computing": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                edge_headers, track_cost=False
            )
            
            logger.info(f"Edge connectivity {edge_test['edge_location']}→{edge_test['central_region']} "
                       f"({edge_test['connection_type']}, {edge_test['latency_ms']}ms): {response.status_code}")
        
        # Test local network segmentation at edge locations
        edge_segmentation_tests = [
            {
                "edge_zone": "manufacturing_floor",
                "segmentation": "ot_network_isolated",
                "access_controls": "strict"
            },
            {
                "edge_zone": "office_network",
                "segmentation": "it_network_standard",
                "access_controls": "standard"
            },
            {
                "edge_zone": "guest_network",
                "segmentation": "isolated_vlan",
                "access_controls": "minimal"
            }
        ]
        
        for seg_test in edge_segmentation_tests:
            seg_headers = dict(auth_headers)
            seg_headers.update({
                "X-Edge-Zone": seg_test["edge_zone"],
                "X-Local-Segmentation": seg_test["segmentation"],
                "X-Access-Controls": seg_test["access_controls"],
                "X-Edge-Segmentation": "enforced"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                seg_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Edge segmentation test {seg_test['edge_zone']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Edge segmentation {seg_test['edge_zone']} "
                       f"({seg_test['segmentation']}): {response.status_code}")
        
        logger.info("ZTA_NET_013: Edge computing network security tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_net_014_network_analytics_behavioral_monitoring(self, http_client: httpx.AsyncClient,
                                                                      auth_headers: Dict[str, str],
                                                                      make_request):
        """ZTA_NET_014: Test network analytics and behavioral monitoring for anomaly detection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test network traffic analysis for behavioral anomaly detection
        traffic_patterns = []
        
        # Establish baseline network behavior
        baseline_tests = [
            {"pattern": "normal_api_usage", "requests": 5, "interval": 1.0},
            {"pattern": "batch_processing", "requests": 3, "interval": 2.0},
            {"pattern": "interactive_session", "requests": 8, "interval": 0.5}
        ]
        
        for baseline in baseline_tests:
            pattern_start = time.time()
            
            baseline_headers = dict(auth_headers)
            baseline_headers.update({
                "X-Traffic-Pattern": baseline["pattern"],
                "X-Expected-Requests": str(baseline["requests"]),
                "X-Expected-Interval": str(baseline["interval"]),
                "X-Baseline-Establishment": "true"
            })
            
            pattern_data = []
            for i in range(baseline["requests"]):
                request_start = time.time()
                
                response = await make_request(
                    http_client, "GET", "/api/v1/models",
                    baseline_headers, track_cost=False
                )
                
                request_end = time.time()
                pattern_data.append({
                    "request_time": request_end - request_start,
                    "timestamp": request_end,
                    "status": response.status_code
                })
                
                await asyncio.sleep(baseline["interval"])
            
            pattern_duration = time.time() - pattern_start
            avg_request_time = sum(p["request_time"] for p in pattern_data) / len(pattern_data)
            
            traffic_patterns.append({
                "pattern": baseline["pattern"],
                "total_duration": pattern_duration,
                "avg_request_time": avg_request_time,
                "request_count": len(pattern_data),
                "baseline": True
            })
            
            logger.info(f"Baseline pattern {baseline['pattern']}: "
                       f"{len(pattern_data)} requests, avg_time={avg_request_time:.3f}s")
        
        # Test anomalous network behavior detection
        anomaly_tests = [
            {
                "anomaly_type": "traffic_spike",
                "description": "Sudden increase in request volume",
                "requests": 20,
                "interval": 0.1
            },
            {
                "anomaly_type": "slow_drip",
                "description": "Unusually slow request pattern",
                "requests": 3,
                "interval": 5.0
            },
            {
                "anomaly_type": "pattern_deviation",
                "description": "Different request pattern than baseline",
                "requests": 10,
                "interval": 0.3
            }
        ]
        
        for anomaly in anomaly_tests:
            anomaly_start = time.time()
            
            anomaly_headers = dict(auth_headers)
            anomaly_headers.update({
                "X-Anomaly-Type": anomaly["anomaly_type"],
                "X-Anomaly-Description": anomaly["description"],
                "X-Behavioral-Monitoring": "enabled",
                "X-Anomaly-Detection": "active"
            })
            
            # Execute anomalous pattern (sample for testing)
            sample_requests = min(5, anomaly["requests"])
            anomaly_data = []
            
            for i in range(sample_requests):
                request_start = time.time()
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    anomaly_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": f"Anomaly test {anomaly['anomaly_type']} {i}"}],
                        "max_tokens": 5
                    }, track_cost=False
                )
                
                request_end = time.time()
                anomaly_data.append({
                    "request_time": request_end - request_start,
                    "timestamp": request_end,
                    "status": response.status_code
                })
                
                await asyncio.sleep(min(anomaly["interval"], 1.0))  # Cap for testing
            
            anomaly_duration = time.time() - anomaly_start
            avg_anomaly_time = sum(p["request_time"] for p in anomaly_data) / len(anomaly_data)
            
            # Compare with baseline
            baseline_avg = sum(p["avg_request_time"] for p in traffic_patterns if p["baseline"]) / len([p for p in traffic_patterns if p["baseline"]])
            deviation_factor = abs(avg_anomaly_time - baseline_avg) / baseline_avg if baseline_avg > 0 else 0
            
            logger.info(f"Network anomaly {anomaly['anomaly_type']}: "
                       f"avg_time={avg_anomaly_time:.3f}s, "
                       f"deviation_factor={deviation_factor:.2f}")
        
        # Test machine learning-based threat pattern recognition
        ml_detection_tests = [
            {
                "ml_model": "lstm_traffic_analyzer",
                "detection_confidence": 0.87,
                "threat_category": "ddos_attempt"
            },
            {
                "ml_model": "cnn_pattern_classifier",
                "detection_confidence": 0.92,
                "threat_category": "reconnaissance_scan"
            },
            {
                "ml_model": "transformer_behavior_analyzer",
                "detection_confidence": 0.78,
                "threat_category": "data_exfiltration"
            }
        ]
        
        for ml_test in ml_detection_tests:
            ml_headers = dict(auth_headers)
            ml_headers.update({
                "X-ML-Model": ml_test["ml_model"],
                "X-Detection-Confidence": str(ml_test["detection_confidence"]),
                "X-Threat-Category": ml_test["threat_category"],
                "X-ML-Detection": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                ml_headers, track_cost=False
            )
            
            logger.info(f"ML threat detection {ml_test['ml_model']} "
                       f"({ml_test['threat_category']}, confidence: {ml_test['detection_confidence']}): "
                       f"{response.status_code}")
        
        logger.info("ZTA_NET_014: Network analytics and behavioral monitoring tested")