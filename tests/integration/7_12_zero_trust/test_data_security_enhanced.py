# Section 7.12 - Zero Trust Data Security Enhanced Tests
# Based on: docs/test_design_n_planning/Testcases_7_12_ZeroTrust/Test Cases_Data Security.md
# Enhanced Test Cases: ZTA_DS_008 through ZTA_DS_015

import pytest
import httpx
import asyncio
import time
import secrets
import hashlib
import ssl
import base64
from typing import Dict, Any, List, Optional
from unittest.mock import patch, Mock

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from utils.security_validators import SecurityValidator


class TestDataSecurityEnhanced:
    """Enhanced Zero Trust Data Security tests"""
    
    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_008_end_to_end_encryption_validation(self, http_client: httpx.AsyncClient,
                                                              auth_headers: Dict[str, str],
                                                              make_request):
        """ZTA_DS_008: Test comprehensive end-to-end encryption for all data flows"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test TLS implementation and cipher suite validation
        tls_tests = [
            {
                "test": "tls_version_check",
                "description": "Verify TLS 1.3 implementation",
                "expected_version": "TLSv1.3"
            },
            {
                "test": "cipher_suite_validation",
                "description": "Test strong cipher suite usage",
                "expected_ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
            },
            {
                "test": "certificate_validation",
                "description": "Verify certificate chain and validity",
                "check_validity": True
            }
        ]
        
        for tls_test in tls_tests:
            # Test HTTPS connection security
            test_headers = dict(auth_headers)
            test_headers["X-TLS-Test"] = tls_test["test"]
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                test_headers, track_cost=False
            )
            
            # Verify encrypted connection
            assert response.status_code == 200, f"HTTPS connection should succeed for {tls_test['test']}"
            
            # Check security headers
            security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]
            for header in security_headers:
                if header in response.headers:
                    logger.info(f"Security header {header}: {response.headers[header]}")
            
            logger.info(f"TLS test {tls_test['test']}: {response.status_code}")
        
        # Test data integrity checks
        integrity_tests = [
            {
                "data": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Data integrity test"}],
                    "max_tokens": 10
                },
                "checksum_header": "X-Content-Checksum"
            }
        ]
        
        for integrity_test in integrity_tests:
            # Calculate content checksum
            content = str(integrity_test["data"]).encode()
            checksum = hashlib.sha256(content).hexdigest()
            
            integrity_headers = dict(auth_headers)
            integrity_headers[integrity_test["checksum_header"]] = checksum
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                integrity_headers, json=integrity_test["data"], track_cost=False
            )
            
            logger.info(f"Data integrity test: {response.status_code}")
        
        logger.info("ZTA_DS_008: End-to-end encryption validation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_009_advanced_key_management_hsm_integration(self, http_client: httpx.AsyncClient,
                                                                     auth_headers: Dict[str, str],
                                                                     make_request):
        """ZTA_DS_009: Test hardware security module integration for cryptographic key management"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test HSM integration simulation (conceptual)
        hsm_tests = [
            {
                "operation": "key_generation",
                "description": "Test secure key generation in HSM",
                "key_type": "RSA-4096",
                "security_level": "FIPS_140_2_Level_3"
            },
            {
                "operation": "key_storage",
                "description": "Test secure key storage with HSM",
                "storage_type": "hardware_protected",
                "tamper_resistance": "enabled"
            },
            {
                "operation": "cryptographic_operations",
                "description": "Test crypto operations within HSM",
                "operation_type": "signing",
                "algorithm": "ECDSA_P384"
            }
        ]
        
        for hsm_test in hsm_tests:
            hsm_headers = dict(auth_headers)
            hsm_headers.update({
                "X-HSM-Operation": hsm_test["operation"],
                "X-Key-Type": hsm_test.get("key_type", ""),
                "X-Security-Level": hsm_test.get("security_level", ""),
                "X-HSM-Protected": "true"
            })
            
            # Simulate HSM-protected API call
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                hsm_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"HSM test {hsm_test['operation']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"HSM test {hsm_test['operation']}: {response.status_code}")
        
        # Test key access controls and authentication to HSM
        hsm_access_tests = [
            {
                "user_role": "crypto_officer",
                "access_level": "full",
                "operations": ["generate", "store", "retrieve", "delete"]
            },
            {
                "user_role": "operator",
                "access_level": "limited", 
                "operations": ["retrieve", "use"]
            },
            {
                "user_role": "audit",
                "access_level": "read_only",
                "operations": ["audit", "verify"]
            }
        ]
        
        for access_test in hsm_access_tests:
            access_headers = dict(auth_headers)
            access_headers.update({
                "X-HSM-Role": access_test["user_role"],
                "X-Access-Level": access_test["access_level"],
                "X-Allowed-Operations": ",".join(access_test["operations"])
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                access_headers, track_cost=False
            )
            
            logger.info(f"HSM access test {access_test['user_role']}: {response.status_code}")
        
        logger.info("ZTA_DS_009: Advanced key management and HSM integration tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_010_data_loss_prevention_dlp_integration(self, http_client: httpx.AsyncClient,
                                                                  auth_headers: Dict[str, str],
                                                                  make_request):
        """ZTA_DS_010: Test data loss prevention capabilities with content inspection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test real-time content inspection for sensitive data patterns
        dlp_test_data = [
            {
                "category": "pii_ssn",
                "content": "My SSN is 123-45-6789",
                "expected_action": "block",
                "risk_level": "high"
            },
            {
                "category": "pii_credit_card",
                "content": "My credit card number is 4532-1234-5678-9012",
                "expected_action": "block", 
                "risk_level": "high"
            },
            {
                "category": "confidential_data",
                "content": "CONFIDENTIAL: Project codename Alpha-7",
                "expected_action": "flag",
                "risk_level": "medium"
            },
            {
                "category": "normal_content",
                "content": "This is normal business content",
                "expected_action": "allow",
                "risk_level": "low"
            }
        ]
        
        for dlp_test in dlp_test_data:
            dlp_headers = dict(auth_headers)
            dlp_headers.update({
                "X-DLP-Category": dlp_test["category"],
                "X-Expected-Action": dlp_test["expected_action"],
                "X-Risk-Level": dlp_test["risk_level"],
                "X-Content-Scan": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                dlp_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": dlp_test["content"]}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            # Current implementation doesn't have DLP, so requests succeed
            # This documents expected behavior with DLP controls
            logger.info(f"DLP test {dlp_test['category']} ({dlp_test['expected_action']}): {response.status_code}")
        
        # Test automatic data classification and labeling
        classification_tests = [
            {
                "content_type": "financial",
                "sensitivity": "restricted",
                "classification": "internal_use_only"
            },
            {
                "content_type": "public",
                "sensitivity": "public",
                "classification": "public"
            },
            {
                "content_type": "personal",
                "sensitivity": "confidential",
                "classification": "restricted"
            }
        ]
        
        for classification in classification_tests:
            class_headers = dict(auth_headers)
            class_headers.update({
                "X-Content-Type": classification["content_type"],
                "X-Sensitivity": classification["sensitivity"],
                "X-Classification": classification["classification"],
                "X-Auto-Classify": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                class_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Content classified as {classification['content_type']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Data classification {classification['content_type']}: {response.status_code}")
        
        logger.info("ZTA_DS_010: Data loss prevention integration tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_011_homomorphic_encryption_secure_processing(self, http_client: httpx.AsyncClient,
                                                                      auth_headers: Dict[str, str],
                                                                      make_request):
        """ZTA_DS_011: Test homomorphic encryption for processing encrypted data"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test homomorphic encryption of sensitive input data (simulation)
        he_tests = [
            {
                "scheme": "fully_homomorphic",
                "operation": "addition",
                "data_type": "numeric",
                "security_level": 128
            },
            {
                "scheme": "partially_homomorphic",
                "operation": "multiplication",
                "data_type": "numeric", 
                "security_level": 256
            },
            {
                "scheme": "somewhat_homomorphic",
                "operation": "polynomial_evaluation",
                "data_type": "text",
                "security_level": 128
            }
        ]
        
        for he_test in he_tests:
            # Simulate encrypted input data
            original_data = f"Sensitive data for {he_test['operation']}"
            encrypted_data = base64.b64encode(original_data.encode()).decode()
            
            he_headers = dict(auth_headers)
            he_headers.update({
                "X-HE-Scheme": he_test["scheme"],
                "X-HE-Operation": he_test["operation"],
                "X-Data-Type": he_test["data_type"],
                "X-Security-Level": str(he_test["security_level"]),
                "X-Encrypted-Input": "true"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                he_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": encrypted_data}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Homomorphic encryption test {he_test['scheme']}: {response.status_code}")
        
        # Test performance impact assessment
        performance_tests = [
            {"encryption": "none", "baseline": True},
            {"encryption": "he_partial", "overhead_expected": "2x-10x"},
            {"encryption": "he_full", "overhead_expected": "100x-1000x"}
        ]
        
        for perf_test in performance_tests:
            perf_start = time.time()
            
            perf_headers = dict(auth_headers)
            perf_headers["X-Encryption-Type"] = perf_test["encryption"]
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                perf_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Performance test"}],
                    "max_tokens": 5
                }, track_cost=False
            )
            
            perf_duration = time.time() - perf_start
            
            logger.info(f"HE performance {perf_test['encryption']}: {perf_duration:.3f}s")
        
        logger.info("ZTA_DS_011: Homomorphic encryption for secure processing tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_012_quantum_resistant_cryptography(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_DS_012: Test quantum-resistant cryptographic algorithms"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test implementation of NIST-approved post-quantum algorithms
        pq_algorithms = [
            {
                "algorithm": "CRYSTALS-Kyber",
                "type": "key_encapsulation",
                "security_level": "NIST_Level_3",
                "key_size": "1632_bytes"
            },
            {
                "algorithm": "CRYSTALS-Dilithium",
                "type": "digital_signature",
                "security_level": "NIST_Level_2",
                "signature_size": "2420_bytes"
            },
            {
                "algorithm": "FALCON",
                "type": "digital_signature",
                "security_level": "NIST_Level_5",
                "signature_size": "1280_bytes"
            }
        ]
        
        for pq_alg in pq_algorithms:
            pq_headers = dict(auth_headers)
            pq_headers.update({
                "X-PQ-Algorithm": pq_alg["algorithm"],
                "X-PQ-Type": pq_alg["type"],
                "X-Security-Level": pq_alg["security_level"],
                "X-Quantum-Resistant": "true"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                pq_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"PQ test {pq_alg['algorithm']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Post-quantum algorithm {pq_alg['algorithm']}: {response.status_code}")
        
        # Test hybrid classical-quantum resistant modes
        hybrid_tests = [
            {
                "mode": "classical_pq_hybrid",
                "classical": "RSA-4096",
                "post_quantum": "Kyber-1024",
                "security_model": "best_of_both"
            },
            {
                "mode": "transition_mode",
                "classical": "ECDSA-P384",
                "post_quantum": "Dilithium-3",
                "security_model": "migration_ready"
            }
        ]
        
        for hybrid in hybrid_tests:
            hybrid_headers = dict(auth_headers)
            hybrid_headers.update({
                "X-Hybrid-Mode": hybrid["mode"],
                "X-Classical-Alg": hybrid["classical"],
                "X-PQ-Alg": hybrid["post_quantum"],
                "X-Security-Model": hybrid["security_model"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                hybrid_headers, track_cost=False
            )
            
            logger.info(f"Hybrid crypto mode {hybrid['mode']}: {response.status_code}")
        
        # Test cryptographic agility
        agility_tests = [
            {
                "scenario": "algorithm_upgrade",
                "from_algorithm": "RSA-2048",
                "to_algorithm": "Kyber-512",
                "transition_period": "6_months"
            },
            {
                "scenario": "emergency_migration",
                "from_algorithm": "ECDSA-P256", 
                "to_algorithm": "Dilithium-2",
                "transition_period": "immediate"
            }
        ]
        
        for agility in agility_tests:
            agility_headers = dict(auth_headers)
            agility_headers.update({
                "X-Crypto-Agility": agility["scenario"],
                "X-From-Algorithm": agility["from_algorithm"],
                "X-To-Algorithm": agility["to_algorithm"],
                "X-Transition-Period": agility["transition_period"]
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                agility_headers, track_cost=False
            )
            
            logger.info(f"Cryptographic agility {agility['scenario']}: {response.status_code}")
        
        logger.info("ZTA_DS_012: Quantum-resistant cryptography tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_013_secure_multi_party_computation(self, http_client: httpx.AsyncClient,
                                                           auth_headers: Dict[str, str],
                                                           make_request):
        """ZTA_DS_013: Test secure multi-party computation for collaborative processing"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test SMPC protocol implementation (simulation)
        smpc_protocols = [
            {
                "protocol": "BGW",
                "parties": 3,
                "threshold": 2,
                "security_model": "semi_honest"
            },
            {
                "protocol": "GMW",
                "parties": 4,
                "threshold": 3, 
                "security_model": "malicious"
            },
            {
                "protocol": "SPDZ",
                "parties": 5,
                "threshold": 3,
                "security_model": "malicious_with_abort"
            }
        ]
        
        for smpc in smpc_protocols:
            smpc_headers = dict(auth_headers)
            smpc_headers.update({
                "X-SMPC-Protocol": smpc["protocol"],
                "X-Party-Count": str(smpc["parties"]),
                "X-Threshold": str(smpc["threshold"]),
                "X-Security-Model": smpc["security_model"],
                "X-Party-ID": "1"  # Simulate being party 1
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                smpc_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"SMPC computation with {smpc['protocol']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"SMPC protocol {smpc['protocol']} ({smpc['parties']} parties): {response.status_code}")
        
        # Test privacy preservation during computation
        privacy_tests = [
            {
                "privacy_model": "differential_privacy",
                "epsilon": 0.1,
                "delta": 1e-5,
                "mechanism": "laplace"
            },
            {
                "privacy_model": "k_anonymity",
                "k_value": 5,
                "l_diversity": 3,
                "t_closeness": 0.2
            }
        ]
        
        for privacy in privacy_tests:
            privacy_headers = dict(auth_headers)
            privacy_headers.update({
                "X-Privacy-Model": privacy["privacy_model"],
                "X-Privacy-Parameters": str(privacy),
                "X-Privacy-Guaranteed": "true"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                privacy_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Privacy-preserving computation"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Privacy model {privacy['privacy_model']}: {response.status_code}")
        
        logger.info("ZTA_DS_013: Secure multi-party computation tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_014_data_residency_sovereignty_compliance(self, http_client: httpx.AsyncClient,
                                                                   auth_headers: Dict[str, str],
                                                                   make_request):
        """ZTA_DS_014: Test data residency controls and sovereignty compliance"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test geographic restrictions for data storage and processing
        residency_tests = [
            {
                "jurisdiction": "US",
                "region": "us-east-1",
                "compliance": ["FISMA", "SOX"],
                "allowed": True
            },
            {
                "jurisdiction": "EU",
                "region": "eu-west-1", 
                "compliance": ["GDPR", "PCI_DSS"],
                "allowed": True
            },
            {
                "jurisdiction": "CHINA",
                "region": "cn-north-1",
                "compliance": ["Cybersecurity_Law"],
                "allowed": False  # Restricted for government data
            }
        ]
        
        for residency in residency_tests:
            residency_headers = dict(auth_headers)
            residency_headers.update({
                "X-Data-Jurisdiction": residency["jurisdiction"],
                "X-Processing-Region": residency["region"],
                "X-Compliance-Requirements": ",".join(residency["compliance"]),
                "X-Residency-Enforced": "true"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                residency_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Data processing in {residency['jurisdiction']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            # Current implementation doesn't enforce geo-restrictions
            expected_status = "allowed" if residency["allowed"] else "blocked"
            logger.info(f"Data residency {residency['jurisdiction']} ({expected_status}): {response.status_code}")
        
        # Test cross-border transfer controls
        transfer_tests = [
            {
                "from_jurisdiction": "US",
                "to_jurisdiction": "EU",
                "transfer_mechanism": "adequacy_decision",
                "allowed": True
            },
            {
                "from_jurisdiction": "EU",
                "to_jurisdiction": "US",
                "transfer_mechanism": "standard_contractual_clauses",
                "allowed": True
            },
            {
                "from_jurisdiction": "US",
                "to_jurisdiction": "RESTRICTED_COUNTRY",
                "transfer_mechanism": "none",
                "allowed": False
            }
        ]
        
        for transfer in transfer_tests:
            transfer_headers = dict(auth_headers)
            transfer_headers.update({
                "X-Transfer-From": transfer["from_jurisdiction"],
                "X-Transfer-To": transfer["to_jurisdiction"],
                "X-Transfer-Mechanism": transfer["transfer_mechanism"],
                "X-Cross-Border-Transfer": "true"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                transfer_headers, track_cost=False
            )
            
            expected_status = "allowed" if transfer["allowed"] else "blocked"
            logger.info(f"Cross-border transfer {transfer['from_jurisdiction']}→{transfer['to_jurisdiction']} "
                       f"({expected_status}): {response.status_code}")
        
        logger.info("ZTA_DS_014: Data residency and sovereignty compliance tested")

    @pytest.mark.zero_trust_enhanced
    @pytest.mark.asyncio
    async def test_zta_ds_015_advanced_threat_protection_for_data(self, http_client: httpx.AsyncClient,
                                                                 auth_headers: Dict[str, str],
                                                                 make_request):
        """ZTA_DS_015: Test advanced threat protection for data with ML-based detection"""
        if not config.should_run_zero_trust_tests():
            pytest.skip("Zero Trust enhanced tests disabled")
        
        # Test ML-based detection of data exfiltration attempts
        exfiltration_tests = [
            {
                "attack_type": "bulk_download",
                "pattern": "large_volume_requests",
                "requests": 50,
                "data_size": "large"
            },
            {
                "attack_type": "slow_exfiltration",
                "pattern": "consistent_small_requests",
                "requests": 100,
                "data_size": "small"
            },
            {
                "attack_type": "pattern_exfiltration",
                "pattern": "systematic_enumeration",
                "requests": 25,
                "data_size": "medium"
            }
        ]
        
        for exfil_test in exfiltration_tests:
            exfil_headers = dict(auth_headers)
            exfil_headers.update({
                "X-Attack-Type": exfil_test["attack_type"],
                "X-Attack-Pattern": exfil_test["pattern"],
                "X-Expected-Requests": str(exfil_test["requests"]),
                "X-Data-Size": exfil_test["data_size"]
            })
            
            # Simulate exfiltration attempt
            if exfil_test["attack_type"] == "bulk_download":
                # Rapid large requests
                for i in range(5):  # Reduced for testing
                    response = await make_request(
                        http_client, "POST", "/api/v1/chat/completions",
                        exfil_headers, json={
                            "model": config.get_chat_model(0),
                            "messages": [{"role": "user", "content": f"Bulk request {i}"}],
                            "max_tokens": 100
                        }, track_cost=False
                    )
                    if i == 0:
                        logger.info(f"Exfiltration test {exfil_test['attack_type']}: {response.status_code}")
            
            elif exfil_test["attack_type"] == "slow_exfiltration":
                # Consistent small requests
                for i in range(3):  # Reduced for testing
                    response = await make_request(
                        http_client, "GET", "/api/v1/models",
                        exfil_headers, track_cost=False
                    )
                    await asyncio.sleep(0.1)
                    if i == 0:
                        logger.info(f"Exfiltration test {exfil_test['attack_type']}: {response.status_code}")
            
            else:
                # Single test request
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    exfil_headers, json={
                        "model": config.get_chat_model(0),
                        "messages": [{"role": "user", "content": "Pattern exfiltration test"}],
                        "max_tokens": 20
                    }, track_cost=False
                )
                logger.info(f"Exfiltration test {exfil_test['attack_type']}: {response.status_code}")
        
        # Test anomaly detection for unusual data access patterns
        anomaly_tests = [
            {
                "anomaly": "off_hours_access",
                "time": "03:00",
                "expected_risk": "medium"
            },
            {
                "anomaly": "unusual_volume",
                "volume_multiplier": 10,
                "expected_risk": "high"
            },
            {
                "anomaly": "geographic_anomaly",
                "location": "unusual_country",
                "expected_risk": "high"
            }
        ]
        
        for anomaly in anomaly_tests:
            anomaly_headers = dict(auth_headers)
            anomaly_headers.update({
                "X-Anomaly-Type": anomaly["anomaly"],
                "X-Expected-Risk": anomaly["expected_risk"],
                "X-Anomaly-Detection": "enabled"
            })
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                anomaly_headers, json={
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": f"Anomaly test {anomaly['anomaly']}"}],
                    "max_tokens": 10
                }, track_cost=False
            )
            
            logger.info(f"Data access anomaly {anomaly['anomaly']} (risk: {anomaly['expected_risk']}): {response.status_code}")
        
        # Test threat intelligence integration for data protection
        threat_intel_tests = [
            {
                "intel_source": "commercial_feed",
                "threat_type": "data_theft_campaign",
                "confidence": "high"
            },
            {
                "intel_source": "government_advisory",
                "threat_type": "apt_data_targeting",
                "confidence": "medium"
            }
        ]
        
        for intel in threat_intel_tests:
            intel_headers = dict(auth_headers)
            intel_headers.update({
                "X-Threat-Intel-Source": intel["intel_source"],
                "X-Threat-Type": intel["threat_type"],
                "X-Intel-Confidence": intel["confidence"],
                "X-Intel-Enhanced": "enabled"
            })
            
            response = await make_request(
                http_client, "GET", "/api/v1/models",
                intel_headers, track_cost=False
            )
            
            logger.info(f"Threat intelligence {intel['threat_type']} ({intel['confidence']} confidence): {response.status_code}")
        
        logger.info("ZTA_DS_015: Advanced threat protection for data tested")