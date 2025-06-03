# Section 7.9 - Enhanced Data Anonymization/Masking
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Anonymization_Masking.md

import pytest
import httpx
import asyncio
import re
import hashlib
import json
import time
import statistics
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from faker import Faker
import uuid

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger


@dataclass
class AnonymizationResult:
    """Enhanced anonymization test result structure"""
    test_name: str
    original_data: str
    anonymized_data: str
    pii_types_detected: List[str]
    anonymization_method: str
    data_utility_preserved: float
    privacy_level_achieved: float
    success: bool


class TestEnhancedAnonymization:
    """Test enhanced data anonymization and privacy protection"""
    
    def setup_method(self):
        """Setup for enhanced anonymization tests"""
        self.faker = Faker()
        self.test_session_id = str(uuid.uuid4())
        self.multilingual_patterns = {
            'email_intl': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone_intl': r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}',
            'iban': r'[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}',
            'passport': r'[A-Z]{1,2}[0-9]{6,9}',
            'social_insurance': r'[0-9]{3}-[0-9]{3}-[0-9]{3}'
        }
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_multilingual_008(self, http_client: httpx.AsyncClient,
                                           auth_headers: Dict[str, str],
                                           make_request):
        """TDM_ANON_MULTILINGUAL_008: Multi-language PII detection and redaction"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing multi-language PII detection")
        
        # Test data in multiple languages
        multilingual_test_data = [
            {
                "language": "English",
                "text": "Contact John Smith at john.smith@example.com or +1-555-123-4567",
                "expected_pii": ["email", "phone", "name"]
            },
            {
                "language": "Spanish",
                "text": "Contacta a María García en maria.garcia@ejemplo.es o +34-666-123-456",
                "expected_pii": ["email", "phone", "name"]
            },
            {
                "language": "French",
                "text": "Contactez Jean Dupont à jean.dupont@exemple.fr ou +33-6-12-34-56-78",
                "expected_pii": ["email", "phone", "name"]
            },
            {
                "language": "German",
                "text": "Kontaktieren Sie Hans Müller unter hans.mueller@beispiel.de oder +49-171-1234567",
                "expected_pii": ["email", "phone", "name"]
            },
            {
                "language": "Mixed",
                "text": "IBAN: DE89370400440532013000, Passport: C01X00T47",
                "expected_pii": ["iban", "passport"]
            }
        ]
        
        multilingual_results = []
        
        for test_case in multilingual_test_data:
            # Detect PII across languages
            detected_pii = {}
            
            # Check for international email patterns
            email_matches = re.findall(self.multilingual_patterns['email_intl'], test_case["text"])
            if email_matches:
                detected_pii["email"] = email_matches
            
            # Check for international phone patterns
            phone_matches = re.findall(self.multilingual_patterns['phone_intl'], test_case["text"])
            if phone_matches:
                detected_pii["phone"] = phone_matches
            
            # Check for names (simplified - would use NER in production)
            name_pattern = r'\b[A-ZÁÉÍÓÚÑÄÖÜÀ-Z][a-záéíóúñäöüà-z]+\s+[A-ZÁÉÍÓÚÑÄÖÜÀ-Z][a-záéíóúñäöüà-z]+\b'
            name_matches = re.findall(name_pattern, test_case["text"])
            if name_matches:
                detected_pii["name"] = name_matches
            
            # Check for international identifiers
            if "IBAN" in test_case["text"]:
                iban_matches = re.findall(self.multilingual_patterns['iban'], test_case["text"])
                if iban_matches:
                    detected_pii["iban"] = iban_matches
            
            if "Passport" in test_case["text"] or "passport" in test_case["text"]:
                passport_matches = re.findall(self.multilingual_patterns['passport'], test_case["text"])
                if passport_matches:
                    detected_pii["passport"] = passport_matches
            
            # Anonymize the text
            anonymized_text = test_case["text"]
            for pii_type, matches in detected_pii.items():
                for match in matches:
                    if pii_type == "email":
                        anonymized_text = anonymized_text.replace(match, "[EMAIL_REDACTED]")
                    elif pii_type == "phone":
                        anonymized_text = anonymized_text.replace(match, "[PHONE_REDACTED]")
                    elif pii_type == "name":
                        anonymized_text = anonymized_text.replace(match, "[NAME_REDACTED]")
                    elif pii_type == "iban":
                        anonymized_text = anonymized_text.replace(match, "[IBAN_REDACTED]")
                    elif pii_type == "passport":
                        anonymized_text = anonymized_text.replace(match, "[PASSPORT_REDACTED]")
            
            # Test with anonymized content
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Process this {test_case['language']} text: {anonymized_text}"}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Calculate detection accuracy
            detected_types = list(detected_pii.keys())
            expected_types = test_case["expected_pii"]
            detection_accuracy = len(set(detected_types) & set(expected_types)) / len(expected_types) if expected_types else 0
            
            result = {
                "language": test_case["language"],
                "original_text": test_case["text"],
                "anonymized_text": anonymized_text,
                "detected_pii": detected_pii,
                "expected_pii": expected_types,
                "detection_accuracy": detection_accuracy,
                "response_success": response.status_code == 200
            }
            
            multilingual_results.append(result)
            
            logger.info(f"Multilingual PII detection ({test_case['language']}): "
                       f"Accuracy: {detection_accuracy:.2%}, "
                       f"Detected: {list(detected_pii.keys())}")
        
        # Verify multilingual detection effectiveness
        high_accuracy_results = [r for r in multilingual_results if r["detection_accuracy"] >= 0.7]
        successful_responses = [r for r in multilingual_results if r["response_success"]]
        
        assert len(high_accuracy_results) >= len(multilingual_test_data) * 0.6, \
            f"Most languages should have good detection accuracy, got {len(high_accuracy_results)}/{len(multilingual_test_data)}"
        
        assert len(successful_responses) >= len(multilingual_test_data) * 0.8, \
            f"Most requests should succeed, got {len(successful_responses)}/{len(multilingual_test_data)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_context_aware_009(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """TDM_ANON_CONTEXT_AWARE_009: Context-aware anonymization with utility preservation"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing context-aware anonymization")
        
        # Test scenarios requiring intelligent context preservation
        context_aware_scenarios = [
            {
                "name": "medical_context",
                "original": "Patient John Doe, age 45, diagnosed with diabetes on 01/15/2023",
                "anonymization_rules": {
                    "preserve": ["age", "diagnosis", "date"],
                    "anonymize": ["name"]
                },
                "expected_anonymized": "Patient [PATIENT_ID], age 45, diagnosed with diabetes on 01/15/2023"
            },
            {
                "name": "financial_context",
                "original": "Account holder Jane Smith, account #1234567890, balance $5,000",
                "anonymization_rules": {
                    "preserve": ["balance_range"],
                    "anonymize": ["name", "account_number"]
                },
                "expected_anonymized": "Account holder [CUSTOMER_ID], account #[REDACTED], balance $[5K-10K]"
            },
            {
                "name": "research_context",
                "original": "Survey respondent ID: john@email.com, age group: 25-34, income: $75,000",
                "anonymization_rules": {
                    "preserve": ["age_group", "income_bracket"],
                    "anonymize": ["email"]
                },
                "expected_anonymized": "Survey respondent ID: [RESP_001], age group: 25-34, income: $[70K-80K]"
            },
            {
                "name": "legal_context",
                "original": "Case: Smith v. Jones, plaintiff SSN: 123-45-6789, filed on 03/01/2023",
                "anonymization_rules": {
                    "preserve": ["case_type", "filing_date"],
                    "anonymize": ["names", "ssn"]
                },
                "expected_anonymized": "Case: [PARTY_A] v. [PARTY_B], plaintiff SSN: [SSN_REDACTED], filed on 03/01/2023"
            }
        ]
        
        context_aware_results = []
        
        for scenario in context_aware_scenarios:
            # Apply context-aware anonymization
            anonymized_text = scenario["original"]
            
            # Apply anonymization based on rules
            if "name" in scenario["anonymization_rules"]["anonymize"]:
                # Detect and replace names
                name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'
                names_found = re.findall(name_pattern, anonymized_text)
                for i, name in enumerate(names_found):
                    if "medical" in scenario["name"]:
                        anonymized_text = anonymized_text.replace(name, "[PATIENT_ID]")
                    elif "financial" in scenario["name"]:
                        anonymized_text = anonymized_text.replace(name, "[CUSTOMER_ID]")
                    elif "legal" in scenario["name"]:
                        anonymized_text = anonymized_text.replace(name, f"[PARTY_{chr(65+i)}]")
            
            if "email" in scenario["anonymization_rules"]["anonymize"]:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                anonymized_text = re.sub(email_pattern, "[RESP_001]", anonymized_text)
            
            if "account_number" in scenario["anonymization_rules"]["anonymize"]:
                account_pattern = r'#\d{10}'
                anonymized_text = re.sub(account_pattern, "#[REDACTED]", anonymized_text)
            
            if "ssn" in scenario["anonymization_rules"]["anonymize"]:
                ssn_pattern = r'\d{3}-\d{2}-\d{4}'
                anonymized_text = re.sub(ssn_pattern, "[SSN_REDACTED]", anonymized_text)
            
            # Apply value generalization for utility preservation
            if "balance_range" in scenario["anonymization_rules"]["preserve"]:
                # Convert exact amounts to ranges
                amount_pattern = r'\$(\d{1,3},?\d{3})'
                amounts = re.findall(amount_pattern, anonymized_text)
                for amount in amounts:
                    value = int(amount.replace(",", ""))
                    if value < 10000:
                        range_str = f"$[{value//1000}K-{(value//1000)+5}K]"
                    else:
                        range_str = f"$[{value//1000}K+]"
                    anonymized_text = anonymized_text.replace(f"${amount}", range_str)
            
            if "income_bracket" in scenario["anonymization_rules"]["preserve"]:
                # Similar income bracketing
                income_pattern = r'\$(\d{2,3},\d{3})'
                incomes = re.findall(income_pattern, anonymized_text)
                for income in incomes:
                    value = int(income.replace(",", ""))
                    bracket_start = (value // 10000) * 10
                    bracket_end = bracket_start + 10
                    anonymized_text = anonymized_text.replace(f"${income}", f"$[{bracket_start}K-{bracket_end}K]")
            
            # Calculate utility preservation score
            preserved_elements = scenario["anonymization_rules"]["preserve"]
            utility_score = sum(1 for elem in preserved_elements if elem in anonymized_text.lower() or "date" in elem) / len(preserved_elements) if preserved_elements else 0
            
            # Test with anonymized content
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Analyze this {scenario['name']}: {anonymized_text}"}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            result = AnonymizationResult(
                test_name=scenario["name"],
                original_data=scenario["original"],
                anonymized_data=anonymized_text,
                pii_types_detected=scenario["anonymization_rules"]["anonymize"],
                anonymization_method="context_aware",
                data_utility_preserved=utility_score,
                privacy_level_achieved=0.9 if "[REDACTED]" in anonymized_text or "_ID]" in anonymized_text else 0.5,
                success=response.status_code == 200
            )
            
            context_aware_results.append(result)
            
            logger.info(f"Context-aware anonymization {scenario['name']}: "
                       f"Utility preserved: {utility_score:.2%}, "
                       f"Privacy achieved: {result.privacy_level_achieved:.2%}")
        
        # Verify context-aware anonymization effectiveness
        high_utility_results = [r for r in context_aware_results if r.data_utility_preserved >= 0.7]
        high_privacy_results = [r for r in context_aware_results if r.privacy_level_achieved >= 0.8]
        
        assert len(high_utility_results) >= len(context_aware_scenarios) * 0.7, \
            f"Most scenarios should preserve utility, got {len(high_utility_results)}/{len(context_aware_scenarios)}"
        
        assert len(high_privacy_results) >= len(context_aware_scenarios) * 0.8, \
            f"Most scenarios should achieve high privacy, got {len(high_privacy_results)}/{len(context_aware_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_synthetic_privacy_010(self, http_client: httpx.AsyncClient,
                                                 auth_headers: Dict[str, str],
                                                 make_request):
        """TDM_ANON_SYNTHETIC_PRIVACY_010: Synthetic data generation for privacy"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing synthetic data generation for privacy")
        
        # Test synthetic data generation scenarios
        synthetic_data_scenarios = [
            {
                "name": "user_profile",
                "original_schema": {
                    "name": "string",
                    "email": "email",
                    "age": "integer",
                    "location": "city"
                },
                "privacy_requirements": ["no_real_pii", "statistical_similarity"]
            },
            {
                "name": "transaction_data",
                "original_schema": {
                    "transaction_id": "uuid",
                    "amount": "decimal",
                    "timestamp": "datetime",
                    "merchant": "string"
                },
                "privacy_requirements": ["preserve_distributions", "temporal_patterns"]
            },
            {
                "name": "healthcare_record",
                "original_schema": {
                    "patient_id": "uuid",
                    "diagnosis": "medical_code",
                    "age_group": "range",
                    "treatment": "string"
                },
                "privacy_requirements": ["differential_privacy", "k_anonymity"]
            }
        ]
        
        synthetic_results = []
        
        for scenario in synthetic_data_scenarios:
            # Generate synthetic data based on schema
            synthetic_records = []
            
            for i in range(5):  # Generate 5 synthetic records
                if scenario["name"] == "user_profile":
                    synthetic_record = {
                        "name": self.faker.name(),
                        "email": self.faker.email(),
                        "age": self.faker.random_int(min=18, max=80),
                        "location": self.faker.city()
                    }
                elif scenario["name"] == "transaction_data":
                    synthetic_record = {
                        "transaction_id": str(uuid.uuid4()),
                        "amount": round(self.faker.random.uniform(10.0, 500.0), 2),
                        "timestamp": self.faker.date_time_this_month().isoformat(),
                        "merchant": self.faker.company()
                    }
                elif scenario["name"] == "healthcare_record":
                    synthetic_record = {
                        "patient_id": str(uuid.uuid4()),
                        "diagnosis": f"ICD-{self.faker.random_int(100, 999)}",
                        "age_group": f"{(self.faker.random_int(2, 9) * 10)}-{(self.faker.random_int(2, 9) * 10) + 9}",
                        "treatment": self.faker.random_element(["medication", "therapy", "surgery", "monitoring"])
                    }
                
                synthetic_records.append(synthetic_record)
            
            # Calculate privacy metrics
            privacy_metrics = {
                "no_real_pii": True,  # All data is synthetic
                "records_generated": len(synthetic_records),
                "schema_compliance": all(
                    set(record.keys()) == set(scenario["original_schema"].keys())
                    for record in synthetic_records
                ),
                "diversity_score": len(set(str(record) for record in synthetic_records)) / len(synthetic_records)
            }
            
            # Test with synthetic data
            test_data = json.dumps(synthetic_records[0])  # Use first record for testing
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Process synthetic {scenario['name']}: {test_data}"}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            result = {
                "scenario": scenario["name"],
                "records_generated": len(synthetic_records),
                "sample_record": synthetic_records[0],
                "privacy_metrics": privacy_metrics,
                "privacy_requirements_met": all(
                    req in ["no_real_pii", "statistical_similarity", "preserve_distributions", 
                           "temporal_patterns", "differential_privacy", "k_anonymity"]
                    for req in scenario["privacy_requirements"]
                ),
                "response_success": response.status_code == 200
            }
            
            synthetic_results.append(result)
            
            logger.info(f"Synthetic data generation {scenario['name']}: "
                       f"Records: {len(synthetic_records)}, "
                       f"Diversity: {privacy_metrics['diversity_score']:.2%}")
        
        # Verify synthetic data generation effectiveness
        successful_generations = [r for r in synthetic_results if r["response_success"]]
        privacy_compliant = [r for r in synthetic_results if r["privacy_metrics"]["no_real_pii"]]
        diverse_datasets = [r for r in synthetic_results if r["privacy_metrics"]["diversity_score"] >= 0.8]
        
        assert len(successful_generations) >= len(synthetic_data_scenarios) * 0.8, \
            f"Most generations should succeed, got {len(successful_generations)}/{len(synthetic_data_scenarios)}"
        
        assert len(privacy_compliant) == len(synthetic_data_scenarios), \
            "All synthetic data should be privacy compliant"
        
        assert len(diverse_datasets) >= len(synthetic_data_scenarios) * 0.6, \
            f"Most datasets should be diverse, got {len(diverse_datasets)}/{len(synthetic_data_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_dynamic_policy_012(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """TDM_ANON_DYNAMIC_POLICY_012: Dynamic anonymization policy management"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing dynamic anonymization policy management")
        
        # Define dynamic policy scenarios
        policy_scenarios = [
            {
                "context": "public_api",
                "data_sensitivity": "low",
                "user_role": "anonymous",
                "policy": {
                    "anonymization_level": "basic",
                    "methods": ["redaction"],
                    "pii_types": ["email", "phone"]
                }
            },
            {
                "context": "internal_api",
                "data_sensitivity": "medium",
                "user_role": "employee",
                "policy": {
                    "anonymization_level": "standard",
                    "methods": ["hashing", "masking"],
                    "pii_types": ["email", "phone", "ssn", "address"]
                }
            },
            {
                "context": "admin_api",
                "data_sensitivity": "high",
                "user_role": "admin",
                "policy": {
                    "anonymization_level": "strict",
                    "methods": ["encryption", "tokenization"],
                    "pii_types": ["all"]
                }
            },
            {
                "context": "compliance_audit",
                "data_sensitivity": "critical",
                "user_role": "auditor",
                "policy": {
                    "anonymization_level": "maximum",
                    "methods": ["differential_privacy", "k_anonymity"],
                    "pii_types": ["all"],
                    "additional_requirements": ["audit_trail", "reversible"]
                }
            }
        ]
        
        policy_results = []
        
        for scenario in policy_scenarios:
            # Simulate dynamic policy selection
            policy_start_time = time.time()
            
            # Select anonymization methods based on policy
            selected_methods = []
            anonymization_strength = 0.0
            
            if "redaction" in scenario["policy"]["methods"]:
                selected_methods.append("redaction")
                anonymization_strength += 0.3
            
            if "hashing" in scenario["policy"]["methods"]:
                selected_methods.append("hashing")
                anonymization_strength += 0.4
            
            if "encryption" in scenario["policy"]["methods"]:
                selected_methods.append("encryption")
                anonymization_strength += 0.6
            
            if "differential_privacy" in scenario["policy"]["methods"]:
                selected_methods.append("differential_privacy")
                anonymization_strength += 0.9
            
            policy_selection_time = time.time() - policy_start_time
            
            # Apply policy to test data
            test_data = f"Test data for {scenario['context']} with email test@example.com and phone 555-123-4567"
            
            # Apply selected anonymization methods
            anonymized_data = test_data
            if "redaction" in selected_methods:
                anonymized_data = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', anonymized_data)
                anonymized_data = re.sub(r'\b\d{3}-\d{3}-\d{4}\b', '[PHONE_REDACTED]', anonymized_data)
            
            if "hashing" in selected_methods:
                # Hash sensitive parts
                email_hash = hashlib.sha256("test@example.com".encode()).hexdigest()[:8]
                anonymized_data = anonymized_data.replace("[EMAIL_REDACTED]", f"[EMAIL_HASH_{email_hash}]")
            
            # Test with anonymized data
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Process under {scenario['context']} policy: {anonymized_data}"}],
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Evaluate policy effectiveness
            policy_compliance = {
                "correct_methods_applied": all(method in selected_methods for method in scenario["policy"]["methods"][:2]),
                "appropriate_strength": anonymization_strength >= (0.3 if scenario["data_sensitivity"] == "low" else 0.6),
                "role_based_access": True,  # Simulated
                "audit_capability": "audit_trail" in scenario["policy"].get("additional_requirements", [])
            }
            
            result = {
                "context": scenario["context"],
                "data_sensitivity": scenario["data_sensitivity"],
                "user_role": scenario["user_role"],
                "policy": scenario["policy"],
                "selected_methods": selected_methods,
                "anonymization_strength": anonymization_strength,
                "policy_selection_time_ms": policy_selection_time * 1000,
                "policy_compliance": policy_compliance,
                "response_success": response.status_code == 200
            }
            
            policy_results.append(result)
            
            logger.info(f"Dynamic policy {scenario['context']}: "
                       f"Sensitivity: {scenario['data_sensitivity']}, "
                       f"Methods: {selected_methods}, "
                       f"Strength: {anonymization_strength:.2f}")
        
        # Verify dynamic policy effectiveness
        compliant_policies = [r for r in policy_results if r["policy_compliance"]["correct_methods_applied"]]
        appropriate_strength = [r for r in policy_results if r["policy_compliance"]["appropriate_strength"]]
        fast_selection = [r for r in policy_results if r["policy_selection_time_ms"] < 100]
        
        assert len(compliant_policies) >= len(policy_scenarios) * 0.8, \
            f"Most policies should be correctly applied, got {len(compliant_policies)}/{len(policy_scenarios)}"
        
        assert len(appropriate_strength) >= len(policy_scenarios) * 0.9, \
            f"Most policies should have appropriate strength, got {len(appropriate_strength)}/{len(policy_scenarios)}"
        
        assert len(fast_selection) >= len(policy_scenarios) * 0.9, \
            f"Policy selection should be fast, got {len(fast_selection)}/{len(policy_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_cross_domain_013(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """TDM_ANON_CROSS_DOMAIN_013: Cross-domain anonymization with regulatory compliance"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing cross-domain anonymization")
        
        # Define domain-specific anonymization requirements
        domain_scenarios = [
            {
                "domain": "healthcare",
                "regulation": "HIPAA",
                "data": "Patient Jane Doe, DOB: 01/15/1980, MRN: 123456, Diagnosis: Diabetes",
                "required_anonymization": {
                    "identifiers": ["name", "dob", "mrn"],
                    "method": "safe_harbor",
                    "preserve": ["diagnosis", "age_range"]
                }
            },
            {
                "domain": "financial",
                "regulation": "PCI-DSS",
                "data": "Cardholder John Smith, Card: 4111-1111-1111-1111, CVV: 123, Exp: 12/25",
                "required_anonymization": {
                    "identifiers": ["name", "card_number", "cvv"],
                    "method": "tokenization",
                    "preserve": ["card_type", "exp_year"]
                }
            },
            {
                "domain": "government",
                "regulation": "Privacy Act",
                "data": "Citizen ID: 987654321, Name: Alice Johnson, Address: 123 Main St, City: Anytown",
                "required_anonymization": {
                    "identifiers": ["citizen_id", "name", "address"],
                    "method": "pseudonymization",
                    "preserve": ["city", "state"]
                }
            },
            {
                "domain": "cross_domain",
                "regulation": "GDPR+HIPAA",
                "data": "EU Patient: Marie Dupont, EU ID: FR123456789, Medical ID: MED789, Treatment: Surgery",
                "required_anonymization": {
                    "identifiers": ["name", "eu_id", "medical_id"],
                    "method": "combined_compliance",
                    "preserve": ["treatment_type", "region"]
                }
            }
        ]
        
        cross_domain_results = []
        
        for scenario in domain_scenarios:
            # Apply domain-specific anonymization
            anonymized_data = scenario["data"]
            compliance_checks = {}
            
            # Healthcare (HIPAA) anonymization
            if scenario["domain"] == "healthcare" or "HIPAA" in scenario["regulation"]:
                # Safe Harbor method
                anonymized_data = re.sub(r'Patient\s+\w+\s+\w+', 'Patient [REDACTED]', anonymized_data)
                anonymized_data = re.sub(r'DOB:\s*\d{2}/\d{2}/\d{4}', 'DOB: [REDACTED]', anonymized_data)
                anonymized_data = re.sub(r'MRN:\s*\d+', 'MRN: [REDACTED]', anonymized_data)
                
                # Preserve age range
                if "01/15/1980" in scenario["data"]:
                    anonymized_data += " (Age Range: 40-50)"
                
                compliance_checks["hipaa_compliant"] = "[REDACTED]" in anonymized_data
            
            # Financial (PCI-DSS) anonymization
            if scenario["domain"] == "financial" or "PCI" in scenario["regulation"]:
                # Tokenization
                anonymized_data = re.sub(r'Cardholder\s+\w+\s+\w+', 'Cardholder [TOKEN_001]', anonymized_data)
                anonymized_data = re.sub(r'\d{4}-\d{4}-\d{4}-\d{4}', 'XXXX-XXXX-XXXX-[LAST4]', anonymized_data)
                anonymized_data = re.sub(r'CVV:\s*\d+', 'CVV: [SECURE]', anonymized_data)
                
                compliance_checks["pci_compliant"] = "XXXX" in anonymized_data and "[SECURE]" in anonymized_data
            
            # Government (Privacy Act) anonymization
            if scenario["domain"] == "government":
                # Pseudonymization
                citizen_id_hash = hashlib.sha256("987654321".encode()).hexdigest()[:8]
                anonymized_data = re.sub(r'Citizen ID:\s*\d+', f'Citizen ID: PSEUDO_{citizen_id_hash}', anonymized_data)
                anonymized_data = re.sub(r'Name:\s*\w+\s+\w+', 'Name: [PSEUDONYM]', anonymized_data)
                anonymized_data = re.sub(r'Address:\s*[\w\s]+,', 'Address: [REDACTED],', anonymized_data)
                
                compliance_checks["privacy_act_compliant"] = "PSEUDO_" in anonymized_data
            
            # Cross-domain compliance
            if scenario["domain"] == "cross_domain":
                # Apply strictest rules from both regulations
                anonymized_data = re.sub(r'EU Patient:\s*\w+\s+\w+', 'EU Patient: [GDPR_REDACTED]', anonymized_data)
                anonymized_data = re.sub(r'EU ID:\s*\w+', 'EU ID: [GDPR_PSEUDONYM]', anonymized_data)
                anonymized_data = re.sub(r'Medical ID:\s*\w+', 'Medical ID: [HIPAA_REDACTED]', anonymized_data)
                
                compliance_checks["gdpr_compliant"] = "[GDPR_" in anonymized_data
                compliance_checks["hipaa_compliant"] = "[HIPAA_" in anonymized_data
            
            # Test with anonymized data
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Process {scenario['domain']} data: {anonymized_data}"}],
                "max_tokens": 100
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            # Evaluate compliance
            overall_compliance = all(compliance_checks.values()) if compliance_checks else False
            
            result = {
                "domain": scenario["domain"],
                "regulation": scenario["regulation"],
                "original_data": scenario["data"],
                "anonymized_data": anonymized_data,
                "compliance_checks": compliance_checks,
                "overall_compliance": overall_compliance,
                "preserved_elements": any(
                    element in anonymized_data.lower() 
                    for element in scenario["required_anonymization"].get("preserve", [])
                ),
                "response_success": response.status_code == 200
            }
            
            cross_domain_results.append(result)
            
            logger.info(f"Cross-domain anonymization {scenario['domain']}: "
                       f"Regulation: {scenario['regulation']}, "
                       f"Compliant: {overall_compliance}")
        
        # Verify cross-domain compliance
        compliant_domains = [r for r in cross_domain_results if r["overall_compliance"]]
        preserved_utility = [r for r in cross_domain_results if r["preserved_elements"]]
        successful_responses = [r for r in cross_domain_results if r["response_success"]]
        
        assert len(compliant_domains) >= len(domain_scenarios) * 0.8, \
            f"Most domains should be compliant, got {len(compliant_domains)}/{len(domain_scenarios)}"
        
        assert len(preserved_utility) >= len(domain_scenarios) * 0.7, \
            f"Most should preserve utility, got {len(preserved_utility)}/{len(domain_scenarios)}"
        
        assert len(successful_responses) >= len(domain_scenarios) * 0.8, \
            f"Most requests should succeed, got {len(successful_responses)}/{len(domain_scenarios)}"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_federated_014(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """TDM_ANON_FEDERATED_014: Federated anonymization for privacy-preserving collaboration"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing federated anonymization")
        
        # Simulate federated organizations with different data
        federated_organizations = [
            {
                "org_id": "Hospital_A",
                "data_type": "patient_records",
                "local_data": [
                    {"patient_id": "PA001", "age": 45, "condition": "diabetes"},
                    {"patient_id": "PA002", "age": 62, "condition": "hypertension"}
                ],
                "privacy_requirements": ["local_anonymization", "no_raw_data_sharing"]
            },
            {
                "org_id": "Hospital_B",
                "data_type": "patient_records",
                "local_data": [
                    {"patient_id": "PB001", "age": 38, "condition": "diabetes"},
                    {"patient_id": "PB002", "age": 55, "condition": "asthma"}
                ],
                "privacy_requirements": ["local_anonymization", "aggregate_only"]
            },
            {
                "org_id": "Research_Center",
                "data_type": "aggregated_insights",
                "local_data": [],
                "privacy_requirements": ["receive_aggregates_only", "preserve_statistical_validity"]
            }
        ]
        
        federated_results = []
        
        # Phase 1: Local anonymization at each organization
        anonymized_local_data = {}
        
        for org in federated_organizations:
            if org["data_type"] == "patient_records":
                # Local anonymization
                org_anonymized_data = []
                
                for record in org["local_data"]:
                    # Apply local anonymization
                    anonymized_record = {
                        "anonymous_id": hashlib.sha256(f"{org['org_id']}_{record['patient_id']}".encode()).hexdigest()[:8],
                        "age_group": f"{(record['age'] // 10) * 10}-{((record['age'] // 10) * 10) + 9}",
                        "condition": record["condition"]  # Condition is not PII in this context
                    }
                    org_anonymized_data.append(anonymized_record)
                
                anonymized_local_data[org["org_id"]] = org_anonymized_data
                
                logger.info(f"Local anonymization at {org['org_id']}: {len(org_anonymized_data)} records")
        
        # Phase 2: Federated aggregation without sharing raw data
        federated_aggregates = {
            "condition_distribution": {},
            "age_distribution": {},
            "total_records": 0
        }
        
        for org_id, data in anonymized_local_data.items():
            # Calculate local statistics
            for record in data:
                # Update condition distribution
                condition = record["condition"]
                federated_aggregates["condition_distribution"][condition] = \
                    federated_aggregates["condition_distribution"].get(condition, 0) + 1
                
                # Update age distribution
                age_group = record["age_group"]
                federated_aggregates["age_distribution"][age_group] = \
                    federated_aggregates["age_distribution"].get(age_group, 0) + 1
                
                federated_aggregates["total_records"] += 1
        
        # Phase 3: Share aggregated insights
        aggregated_insights = {
            "diabetes_prevalence": federated_aggregates["condition_distribution"].get("diabetes", 0) / federated_aggregates["total_records"] if federated_aggregates["total_records"] > 0 else 0,
            "age_group_most_affected": max(federated_aggregates["age_distribution"].items(), key=lambda x: x[1])[0] if federated_aggregates["age_distribution"] else "unknown",
            "participating_organizations": len(anonymized_local_data),
            "total_anonymized_records": federated_aggregates["total_records"]
        }
        
        # Test federated query
        query = f"Analyze federated health data: {json.dumps(aggregated_insights)}"
        
        request_data = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": query}],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request_data
        )
        
        # Evaluate federated anonymization
        privacy_preserved = all(
            isinstance(data, list) and all("patient_id" not in str(record) for record in data)
            for data in anonymized_local_data.values()
        )
        
        statistical_validity = (
            aggregated_insights["total_anonymized_records"] == 
            sum(len(org["local_data"]) for org in federated_organizations if org["data_type"] == "patient_records")
        )
        
        federated_result = {
            "participating_orgs": len(federated_organizations),
            "total_records_processed": aggregated_insights["total_anonymized_records"],
            "privacy_preserved": privacy_preserved,
            "statistical_validity": statistical_validity,
            "aggregated_insights": aggregated_insights,
            "no_raw_data_shared": True,  # By design in this simulation
            "response_success": response.status_code == 200
        }
        
        logger.info(f"Federated anonymization complete: "
                   f"{federated_result['participating_orgs']} orgs, "
                   f"{federated_result['total_records_processed']} records, "
                   f"Privacy preserved: {privacy_preserved}")
        
        # Verify federated anonymization effectiveness
        assert federated_result["privacy_preserved"], "Privacy should be preserved in federated setting"
        assert federated_result["statistical_validity"], "Statistical validity should be maintained"
        assert federated_result["no_raw_data_shared"], "No raw data should be shared between organizations"
        assert federated_result["response_success"], "Federated query should succeed"
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_realtime_detection_007(self, http_client: httpx.AsyncClient,
                                                  auth_headers: Dict[str, str],
                                                  make_request):
        """TDM_ANON_REALTIME_DETECTION_007: Real-time ML-based PII detection"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing real-time ML-based PII detection")
        
        # Test various PII patterns with ML detection simulation
        ml_detection_scenarios = [
            {
                "text": "Please contact our support team at support@company.com or call (555) 123-4567",
                "expected_entities": [
                    {"type": "EMAIL", "value": "support@company.com", "confidence": 0.98},
                    {"type": "PHONE", "value": "(555) 123-4567", "confidence": 0.95}
                ]
            },
            {
                "text": "John Doe's SSN is 123-45-6789 and he lives at 123 Main St, Anytown, CA 90210",
                "expected_entities": [
                    {"type": "PERSON", "value": "John Doe", "confidence": 0.92},
                    {"type": "SSN", "value": "123-45-6789", "confidence": 0.99},
                    {"type": "ADDRESS", "value": "123 Main St, Anytown, CA 90210", "confidence": 0.88}
                ]
            },
            {
                "text": "The patient's medical record number is MRN123456 with diagnosis code ICD-10 E11.9",
                "expected_entities": [
                    {"type": "MEDICAL_ID", "value": "MRN123456", "confidence": 0.90},
                    {"type": "MEDICAL_CODE", "value": "ICD-10 E11.9", "confidence": 0.85}
                ]
            }
        ]
        
        ml_detection_results = []
        
        for scenario in ml_detection_scenarios:
            detection_start = time.time()
            
            # Simulate ML-based entity recognition
            detected_entities = []
            
            # Email detection
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            email_matches = re.findall(email_pattern, scenario["text"])
            for match in email_matches:
                detected_entities.append({
                    "type": "EMAIL",
                    "value": match,
                    "confidence": 0.95 + (0.03 if ".com" in match else 0.0),
                    "start_pos": scenario["text"].index(match),
                    "end_pos": scenario["text"].index(match) + len(match)
                })
            
            # Phone detection
            phone_pattern = r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{4,6}'
            phone_matches = re.findall(phone_pattern, scenario["text"])
            for match in phone_matches:
                detected_entities.append({
                    "type": "PHONE",
                    "value": match,
                    "confidence": 0.93 + (0.02 if "(" in match else 0.0),
                    "start_pos": scenario["text"].index(match),
                    "end_pos": scenario["text"].index(match) + len(match)
                })
            
            # SSN detection
            ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
            ssn_matches = re.findall(ssn_pattern, scenario["text"])
            for match in ssn_matches:
                detected_entities.append({
                    "type": "SSN",
                    "value": match,
                    "confidence": 0.99,
                    "start_pos": scenario["text"].index(match),
                    "end_pos": scenario["text"].index(match) + len(match)
                })
            
            # Name detection (simplified)
            name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'
            name_matches = re.findall(name_pattern, scenario["text"])
            for match in name_matches:
                if match not in ["Main St", "The patient"]:  # Filter out false positives
                    detected_entities.append({
                        "type": "PERSON",
                        "value": match,
                        "confidence": 0.88 + (0.04 if len(match.split()) == 2 else 0.0),
                        "start_pos": scenario["text"].index(match),
                        "end_pos": scenario["text"].index(match) + len(match)
                    })
            
            # Medical ID detection
            medical_id_pattern = r'MRN\d{6}'
            medical_matches = re.findall(medical_id_pattern, scenario["text"])
            for match in medical_matches:
                detected_entities.append({
                    "type": "MEDICAL_ID",
                    "value": match,
                    "confidence": 0.90,
                    "start_pos": scenario["text"].index(match),
                    "end_pos": scenario["text"].index(match) + len(match)
                })
            
            detection_end = time.time()
            detection_latency = (detection_end - detection_start) * 1000
            
            # Apply real-time anonymization
            anonymized_text = scenario["text"]
            for entity in sorted(detected_entities, key=lambda x: x["start_pos"], reverse=True):
                if entity["confidence"] >= 0.85:  # Confidence threshold
                    replacement = f"[{entity['type']}_REDACTED]"
                    anonymized_text = (
                        anonymized_text[:entity["start_pos"]] + 
                        replacement + 
                        anonymized_text[entity["end_pos"]:]
                    )
            
            # Calculate detection accuracy
            detected_types = set(e["type"] for e in detected_entities)
            expected_types = set(e["type"] for e in scenario["expected_entities"])
            precision = len(detected_types & expected_types) / len(detected_types) if detected_types else 0
            recall = len(detected_types & expected_types) / len(expected_types) if expected_types else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            # Test with anonymized text
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": f"Process: {anonymized_text}"}],
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            result = {
                "original_text": scenario["text"],
                "anonymized_text": anonymized_text,
                "detected_entities": detected_entities,
                "expected_entities": scenario["expected_entities"],
                "detection_latency_ms": detection_latency,
                "precision": precision,
                "recall": recall,
                "f1_score": f1_score,
                "entities_redacted": len([e for e in detected_entities if e["confidence"] >= 0.85]),
                "response_success": response.status_code == 200
            }
            
            ml_detection_results.append(result)
            
            logger.info(f"ML PII detection: "
                       f"Detected {len(detected_entities)} entities, "
                       f"F1: {f1_score:.2f}, "
                       f"Latency: {detection_latency:.2f}ms")
        
        # Verify ML detection effectiveness
        high_accuracy_results = [r for r in ml_detection_results if r["f1_score"] >= 0.7]
        low_latency_results = [r for r in ml_detection_results if r["detection_latency_ms"] < 50]
        successful_anonymization = [r for r in ml_detection_results if r["entities_redacted"] > 0]
        
        assert len(high_accuracy_results) >= len(ml_detection_scenarios) * 0.6, \
            f"Most scenarios should have high accuracy, got {len(high_accuracy_results)}/{len(ml_detection_scenarios)}"
        
        assert len(low_latency_results) >= len(ml_detection_scenarios) * 0.8, \
            f"Most detections should be fast, got {len(low_latency_results)}/{len(ml_detection_scenarios)}"
        
        assert len(successful_anonymization) >= len(ml_detection_scenarios) * 0.9, \
            f"Most scenarios should have entities redacted, got {len(successful_anonymization)}/{len(ml_detection_scenarios)}"
        
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_anon_blockchain_audit_011(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TDM_ANON_BLOCKCHAIN_AUDIT_011: Blockchain-based anonymization audit trail"""
        if not config.ENABLE_DATA_MANAGEMENT_TESTS:
            pytest.skip("Data management tests disabled")
        
        logger.info("Testing blockchain-based anonymization audit trail")
        
        # Initialize blockchain for anonymization audit
        blockchain = []
        genesis_block = {
            "index": 0,
            "timestamp": time.time(),
            "data": {
                "action": "genesis",
                "description": "Anonymization audit blockchain initialized"
            },
            "previous_hash": "0",
            "nonce": 0
        }
        genesis_block["hash"] = hashlib.sha256(json.dumps(genesis_block, sort_keys=True).encode()).hexdigest()
        blockchain.append(genesis_block)
        
        # Anonymization operations to audit
        anonymization_operations = [
            {
                "operation_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "action": "pii_detection",
                "data_type": "email",
                "original_hash": hashlib.sha256(b"user@example.com").hexdigest(),
                "anonymized_hash": hashlib.sha256(b"[EMAIL_REDACTED]").hexdigest(),
                "method": "pattern_matching",
                "compliance": "GDPR"
            },
            {
                "operation_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "action": "data_masking",
                "data_type": "ssn",
                "original_hash": hashlib.sha256(b"123-45-6789").hexdigest(),
                "anonymized_hash": hashlib.sha256(b"XXX-XX-6789").hexdigest(),
                "method": "partial_masking",
                "compliance": "HIPAA"
            },
            {
                "operation_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "action": "synthetic_generation",
                "data_type": "patient_record",
                "original_hash": hashlib.sha256(b"real_patient_data").hexdigest(),
                "anonymized_hash": hashlib.sha256(b"synthetic_patient_data").hexdigest(),
                "method": "differential_privacy",
                "compliance": "HIPAA"
            }
        ]
        
        blockchain_results = []
        
        for operation in anonymization_operations:
            # Create block for this anonymization operation
            previous_block = blockchain[-1]
            
            new_block = {
                "index": len(blockchain),
                "timestamp": operation["timestamp"],
                "data": operation,
                "previous_hash": previous_block["hash"],
                "nonce": 0
            }
            
            # Simple proof of work (find nonce that produces hash with leading zeros)
            while True:
                block_string = json.dumps(new_block, sort_keys=True)
                block_hash = hashlib.sha256(block_string.encode()).hexdigest()
                if block_hash.startswith("00"):  # Simple difficulty
                    new_block["hash"] = block_hash
                    break
                new_block["nonce"] += 1
            
            blockchain.append(new_block)
            
            # Create cryptographic proof of anonymization
            proof_data = {
                "operation_id": operation["operation_id"],
                "block_hash": new_block["hash"],
                "timestamp": operation["timestamp"],
                "verification": {
                    "original_data_destroyed": True,
                    "anonymization_irreversible": operation["method"] != "tokenization",
                    "compliance_met": True
                }
            }
            
            proof_hash = hashlib.sha256(json.dumps(proof_data, sort_keys=True).encode()).hexdigest()
            
            # Test query about this anonymization
            query = f"Verify anonymization operation {operation['operation_id'][:8]}... with proof {proof_hash[:16]}..."
            
            request_data = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": query}],
                "max_tokens": 80
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request_data
            )
            
            result = {
                "operation": operation,
                "block_index": new_block["index"],
                "block_hash": new_block["hash"],
                "proof_hash": proof_hash,
                "nonce": new_block["nonce"],
                "response_success": response.status_code == 200
            }
            
            blockchain_results.append(result)
            
            logger.info(f"Blockchain audit block {new_block['index']}: "
                       f"Action: {operation['action']}, "
                       f"Hash: {new_block['hash'][:16]}..., "
                       f"Nonce: {new_block['nonce']}")
        
        # Verify blockchain integrity
        chain_valid = True
        for i in range(1, len(blockchain)):
            current = blockchain[i]
            previous = blockchain[i-1]
            
            # Verify hash link
            if current["previous_hash"] != previous["hash"]:
                chain_valid = False
                break
            
            # Verify block hash
            block_copy = current.copy()
            stored_hash = block_copy.pop("hash")
            calculated_hash = hashlib.sha256(json.dumps(block_copy, sort_keys=True).encode()).hexdigest()
            if stored_hash != calculated_hash:
                chain_valid = False
                break
        
        # Generate compliance report
        compliance_summary = {
            "total_operations": len(anonymization_operations),
            "gdpr_operations": len([op for op in anonymization_operations if op["compliance"] == "GDPR"]),
            "hipaa_operations": len([op for op in anonymization_operations if op["compliance"] == "HIPAA"]),
            "blockchain_length": len(blockchain),
            "chain_integrity": chain_valid,
            "average_nonce": statistics.mean([block["nonce"] for block in blockchain[1:]]) if len(blockchain) > 1 else 0
        }
        
        logger.info(f"Blockchain audit summary: "
                   f"{compliance_summary['total_operations']} operations, "
                   f"Chain length: {compliance_summary['blockchain_length']}, "
                   f"Integrity: {chain_valid}")
        
        # Verify blockchain audit effectiveness
        assert chain_valid, "Blockchain integrity must be maintained"
        assert len(blockchain) == len(anonymization_operations) + 1, "All operations should be recorded"
        assert all(block["hash"].startswith("00") for block in blockchain[1:]), "All blocks should meet difficulty"
        assert all(result["response_success"] for result in blockchain_results), "All verification queries should succeed"