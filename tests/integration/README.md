# GSAi API Integration Testing Framework

This is the **comprehensive integration testing framework** for the GSAi API, implementing **1,259 test cases** across **146 test files** covering functional, security, reliability, performance, data management, and Zero Trust testing categories.

## Test Implementation Summary

Based on comprehensive analysis of all test files (see `inventory.json` for detailed breakdown):

| Section | Test Files | Test Cases | Description |
|---------|------------|------------|-------------|
| **7.2 Functional** | 14 | 165 | Functional and validation testing |
| **7.3 Security** | 45 | 517 | Complete OWASP API Top 10 (2023) + LLM security |
| **7.4 Performance** | 12 | 124 | Performance and load testing |
| **7.5 Reliability** | 23 | 248 | Reliability and error handling |
| **7.9 Data Management** | 21 | 149 | Data management and privacy testing |
| **7.12 Zero Trust** | 31 | 56 | Zero Trust architecture validation |

**Total: 146 Test Files | 1,259 Test Cases**

## Setup Instructions

### 1. Create Python Virtual Environment

```bash
cd tests/integration
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

The `requirements.txt` file has been optimized to include only packages actually used by the test suite, reducing dependencies from 200+ to approximately 25 essential packages.

### 3. Environment Configuration

1. Copy the environment template:
```bash
cp .env.template .env
```

2. Edit `.env` file with your API configuration:
```bash
# Core API Configuration
API_BASE_URL=https://your-api-endpoint.com
TEST_API_KEY=your_test_api_key_here
TEST_ADMIN_API_KEY=your_admin_api_key_here
TEST_EMBEDDING_API_KEY=your_embedding_api_key_here

# Model Configuration
CHAT_MODELS=claude_3_5_sonnet,gemini-2.0-flash,llama3_8b
EMBEDDING_MODELS=cohere_english_v3,text-embedding-005

# Cost Management
DAILY_TEST_BUDGET=50.00
ENABLE_COST_TRACKING=true

# Test Execution Control
ENABLE_SECURITY_TESTS=true
ENABLE_ZERO_TRUST_TESTS=true
ENABLE_PROMPT_INJECTION_TESTS=true
ENABLE_PERFORMANCE_TESTS=true
ENABLE_LOAD_TESTS=false  # Set to true for load testing

# Security Testing Configuration
ENABLE_MULTIMODAL_TESTS=true
MAX_FILE_SIZE_MB=10
SUPPORTED_IMAGE_TYPES=jpg,png,gif,webp
SUPPORTED_DOCUMENT_TYPES=pdf,txt,docx

# Performance Testing Configuration
LOAD_TEST_MAX_USERS=100
LOAD_TEST_DURATION=300
PERFORMANCE_BASELINE_RPS=10
```

## Running Tests

### Run All Tests
```bash
pytest -v
```

### Run by Test Category
```bash
# Functional tests only
pytest -v -m functional

# Security tests only (OWASP API Top 10)
pytest -v -m security

# Zero Trust tests only  
pytest -v -m zero_trust

# Performance tests only
pytest -v -m performance

# Reliability tests only
pytest -v -m reliability

# Data management tests only
pytest -v -m data_management
```

### Run by Test Section
```bash
# Section 7.2 - Functional Testing
pytest -v 7_2_functional/

# Section 7.3 - Security Testing (Complete OWASP API Top 10)
pytest -v 7_3_security/

# Section 7.4 - Performance Testing
pytest -v 7_4_performance/

# Section 7.5 - Reliability Testing
pytest -v 7_5_reliability/

# Section 7.9 - Data Management Testing
pytest -v 7_9_data_management/

# Section 7.12 - Zero Trust Testing
pytest -v 7_12_zero_trust/
```

### Run Specific Test Categories

#### Security Testing (Section 7.3)
```bash
# Run specific OWASP API vulnerability tests
pytest -v 7_3_security/test_owasp_api1_bola.py          # Broken Object Level Authorization
pytest -v 7_3_security/test_owasp_api2_authentication.py # Broken Authentication
pytest -v 7_3_security/test_owasp_api3_data_exposure.py  # Data Exposure
pytest -v 7_3_security/test_owasp_api4_resource_consumption.py # Resource Limits
pytest -v 7_3_security/test_owasp_api5_*_authorization.py # Function Level Authorization
pytest -v 7_3_security/test_owasp_api6_business_flows.py # Business Flow Security
pytest -v 7_3_security/test_owasp_api7_ssrf.py          # Server Side Request Forgery
pytest -v 7_3_security/test_owasp_api8_security_misconfiguration.py # Security Config
pytest -v 7_3_security/test_owasp_api9_inventory_management.py # API Inventory
pytest -v 7_3_security/test_owasp_api10_unsafe_api_consumption.py # Unsafe Consumption

# Run LLM-specific security tests
pytest -v 7_3_security/test_prompt_injection*.py
pytest -v 7_3_security/test_llm_model_security*.py

# Run multimodal security tests
pytest -v 7_3_security/test_multimodal_*.py
```

#### Zero Trust Testing (Section 7.12)
```bash
# Run specific Zero Trust test categories
pytest -v 7_12_zero_trust/test_authentication_authorization*.py
pytest -v 7_12_zero_trust/test_advanced_threat_detection*.py
pytest -v 7_12_zero_trust/test_context_aware_access*.py
pytest -v 7_12_zero_trust/test_data_security*.py
pytest -v 7_12_zero_trust/test_identity_*.py
pytest -v 7_12_zero_trust/test_least_privilege*.py
pytest -v 7_12_zero_trust/test_network_segmentation*.py
pytest -v 7_12_zero_trust/test_observability*.py
pytest -v 7_12_zero_trust/test_security_posture_assessment*.py
```

### Run with Parallel Execution
```bash
# Run tests in parallel (respects PARALLEL_WORKERS setting)
pytest -v -n auto

# Run with specific worker count
pytest -v -n 4
```

### Generate Test Reports
```bash
# Generate HTML report
pytest -v --html=report.html --self-contained-html

# Generate coverage report
pytest -v --cov=. --cov-report=html

# Generate JUnit XML report
pytest -v --junitxml=report.xml
```

## Test Case ID Structure

Each test case follows a consistent naming convention:

- **Section 7.2 (Functional)**: `test_FV_[COMPONENT]_[FEATURE]_[NUMBER]`
- **Section 7.3 (Security)**: `test_SEC_[COMPONENT]_[NUMBER]`, `test_OWASP_API[X]_[FEATURE]_[NUMBER]`
- **Section 7.4 (Performance)**: `test_PERF_[COMPONENT]_[METRIC]_[NUMBER]`
- **Section 7.5 (Reliability)**: `test_REL_[COMPONENT]_[FEATURE]_[NUMBER]`
- **Section 7.9 (Data Management)**: `test_TDM_[COMPONENT]_[FEATURE]_[NUMBER]`
- **Section 7.12 (Zero Trust)**: `test_ZT_[COMPONENT]_[NUMBER]`

## Key Features

### 1. **Comprehensive Test Coverage**
- Complete OWASP API Security Top 10 (2023) implementation
- LLM-specific security testing (prompt injection, jailbreak prevention)
- Zero Trust architecture validation
- Multi-modal content security testing
- Performance and load testing scenarios
- Reliability and chaos engineering tests
- Data privacy and management validation

### 2. **Advanced Testing Capabilities**
- Async test support with pytest-asyncio
- Parallel test execution with pytest-xdist
- Cost tracking and budget management
- Multi-provider testing support
- Comprehensive error handling validation
- Real-time monitoring and observability

### 3. **Security-First Approach**
- Input validation and sanitization testing
- Authentication and authorization verification
- Rate limiting and resource consumption tests
- Security header validation
- Cryptographic implementation testing
- Supply chain security validation

### 4. **Developer-Friendly Features**
- Detailed HTML test reports
- Code coverage analysis
- Comprehensive test fixtures
- Modular test organization
- Clear test naming conventions
- Extensive configuration options

## Test Inventory

A complete inventory of all test files, their imported packages, and test cases is available in:
- `inventory.json` - Raw JSON format
- `inventory_formatted.json` - Pretty-printed format
- `test_inventory.md` - Human-readable documentation

## Architecture

### Core Components
- **config.py** - Centralized configuration management
- **conftest.py** - Global pytest fixtures and setup
- **fixtures/** - Reusable test data and scenarios
- **utils/** - Testing utilities and validators

### Test Organization
Tests are organized by section (7.2, 7.3, etc.) following the GSAi API test plan structure. Each section contains multiple test files focused on specific aspects of testing.

## Dependencies

The framework uses minimal external dependencies:
- **Core**: pytest, pytest-asyncio, httpx
- **Data**: faker, pyjwt
- **Monitoring**: psutil
- **Scientific**: numpy, scipy, scikit-learn (for advanced tests)
- **Media**: pillow (for multimodal tests)

All other functionality leverages Python's extensive standard library.

## Support & Documentation

For detailed information:
- **Test Plan**: See `docs/test_design_n_planning/TestPlan.md`
- **Implementation Plan**: See `docs/test_design_n_planning/TestImplementationPlan.md`
- **Test Cases**: Check `docs/test_design_n_planning/Testcases_*` folders
- **Configuration**: Reference `.env.template` for all options

Last Updated: January 2025