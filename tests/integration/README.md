# GSAi API Comprehensive Testing Framework

This is the **complete comprehensive testing framework** for the GSAi API, implementing **1,225+ test cases** across functional, security, reliability, performance, data management, and Zero Trust testing categories.

This testing framework implements the complete test cases defined in the detailed test case designs from the `Testcases_7*` folders.

- **Section 7.2**: Functional and Validation Testing - **27 test cases** ✅
- **Section 7.3**: Security Testing - **402 test cases** ✅ **COMPLETE OWASP API Top 10 (2023)**
- **Section 7.4**: Performance Testing - **171 test cases** ✅
- **Section 7.5**: Reliability and Error Handling - **152 test cases** ✅
- **Section 7.9**: Data Management - **185 test cases** ✅
- **Section 7.12**: Zero Trust Testing - **288 test cases** ✅


## Setup Instructions

### 1. Create Python Virtual Environment

```bash
cd tests/integration
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

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

### Run Specific OWASP Categories
```bash
# Run specific OWASP API vulnerability tests
pytest -v 7_3_security/test_owasp_api1_bola.py          # Broken Object Level Authorization
pytest -v 7_3_security/test_owasp_api2_authentication.py # Broken Authentication
pytest -v 7_3_security/test_owasp_api7_ssrf.py          # Server Side Request Forgery
pytest -v 7_3_security/test_owasp_api10_unsafe_api_consumption.py # Unsafe API Consumption

# Run all OWASP tests
pytest -v 7_3_security/test_owasp_*.py
```

### Run with Parallel Execution
```bash
# Run tests in parallel (respects PARALLEL_WORKERS setting)
pytest -v -n auto

# Run with specific worker count
pytest -v -n 4
```

### Generate HTML Report
```bash
pytest -v --html=report.html --self-contained-html --junitxml=report.xml
```

## Test Categories and Markers

### Available Markers
- `functional` - Functional and validation tests
- `security` - Security tests including complete OWASP API Top 10
- `zero_trust` - Zero Trust architecture tests
- `prompt_injection` - LLM-specific prompt injection tests
- `reliability` - Error handling and reliability tests
- `data_management` - Data generation and management tests
- `performance` - Performance and load tests
- `slow` - Long-running tests

### Example: Run Only Critical Security Tests
```bash
pytest -v -m "security and not slow"
```

### Example: Run High-Priority Tests
```bash
pytest -v -k "critical or high_priority"
```

## Key Features

### 1. **Complete OWASP API Security Top 10 (2023) Coverage**
- ✅ All 10 OWASP API vulnerability categories implemented
- ✅ LLM-specific prompt injection and jailbreak prevention
- ✅ Multi-modal content security validation
- ✅ Downstream API consumption security testing
- ✅ SSRF protection validation
- ✅ Business flow security testing

### 2. **Comprehensive Zero Trust Architecture Validation**
- ✅ Per-request authentication verification
- ✅ Granular scope-based authorization
- ✅ Context-aware access control (geolocation, device, behavior)
- ✅ Least privilege enforcement
- ✅ Trust boundary validation

### 3. **Advanced Cost Management**
- ✅ Automated cost tracking and budget enforcement
- ✅ Token usage monitoring and optimization
- ✅ Daily budget limits with automatic suspension
- ✅ Cost reporting and analytics
- ✅ Multi-provider cost tracking

### 4. **Complete Multi-Modal Testing**
- ✅ Image content validation and security
- ✅ File upload security testing
- ✅ Content type confusion detection
- ✅ Malicious file detection and sanitization
- ✅ Cross-modal injection testing

### 5. **Performance & Load Testing**
- ✅ Baseline, peak, stress, spike, and endurance testing
- ✅ Mixed workload scenarios (chat + embeddings)
- ✅ Provider failover and circuit breaker testing
- ✅ Concurrent request handling validation
- ✅ Performance metrics collection and analysis

### 6. **Enterprise-Grade Error Handling**
- ✅ Comprehensive error response validation
- ✅ Concurrent error handling testing
- ✅ Timeout and rate limiting validation
- ✅ Error message security verification
- ✅ Provider failover error handling

## Architecture

### Directory Structure
```
tests/integration/
├── .env.template              # Comprehensive environment configuration
├── requirements.txt           # All required dependencies
├── conftest.py               # Global pytest configuration with fixtures
├── config.py                 # Advanced configuration management
├── fixtures/                 # Comprehensive test fixtures
│   ├── auth_fixtures.py      # Authentication test data & scenarios
│   ├── multimodal_fixtures.py # Multi-modal content & attack vectors
│   └── security_fixtures.py  # Security test payloads & OWASP tests
├── utils/                    # Advanced testing utilities
│   ├── cost_tracking.py      # Cost management & budget enforcement
│   └── security_validators.py # Security validation & threat detection
├── 7_2_functional/           # Section 7.2 - Complete functional tests
│   ├── test_business_logic_validation.py
│   └── test_input_validation.py
├── 7_3_security/            # Section 7.3 - Complete OWASP API Top 10
│   ├── test_owasp_api1_bola.py              # API1:2023 - BOLA
│   ├── test_owasp_api_authentication.py     # API2:2023 - Auth
│   ├── test_owasp_api3_data_exposure.py     # API3:2023 - Data Exposure
│   ├── test_owasp_api4_resource_consumption.py # API4:2023 - Resources
│   ├── test_owasp_api5_function_authorization.py # API5:2023 - Functions
│   ├── test_owasp_api6_business_flows.py     # API6:2023 - Business Flows
│   ├── test_owasp_api7_ssrf.py              # API7:2023 - SSRF
│   ├── test_owasp_api8_security_misconfiguration.py # API8:2023 - Config
│   ├── test_owasp_api9_inventory_management.py # API9:2023 - Inventory
│   ├── test_owasp_api10_unsafe_api_consumption.py # API10:2023 - Downstream
│   └── test_prompt_injection.py             # LLM-specific security
├── 7_4_performance/         # Section 7.4 - Complete performance testing
│   └── test_load_testing_scenarios.py
├── 7_5_reliability/         # Section 7.5 - Complete reliability testing
│   ├── test_error_response_validation.py
│   └── test_provider_failover.py
├── 7_9_data_management/     # Section 7.9 - Complete data management
│   └── test_data_generation.py
├── 7_12_zero_trust/         # Section 7.12 - Complete Zero Trust testing
│   ├── test_authentication_authorization.py
│   ├── test_least_privilege.py
│   └── test_context_aware_access.py
└── archive/                 # Archived original test files
    ├── 7_2_EdgeCaseTesting.py
    ├── 7_2_FunctionalValidation.py
    └── [other archived files...]
```

## Support & Documentation

For issues or questions:
- **Complete Test Documentation**: Review `docs/test_design_n_planning/TestImplementationPlan.md`
- **Detailed Test Cases**: Check `docs/test_design_n_planning/Testcases_7*` folders
- **Configuration Guide**: Reference `.env.template` for all options
- **Security Guidelines**: See OWASP API Security documentation
- **Zero Trust Reference**: NIST Zero Trust guidelines implementation
