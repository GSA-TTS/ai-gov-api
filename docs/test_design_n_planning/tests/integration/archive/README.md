# AI Gov API Integration Tests

This directory contains comprehensive integration tests for the AI Gov API that validate real-world API behavior using live endpoints. The tests are aligned with TestPlan.md Section 7 requirements and cover security, functional, reliability, and data privacy testing.

## 🚀 Quick Start

### 1. Setup Python Virtual Environment
```bash
# Navigate to integration tests directory
cd tests/integration

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Edit the `.env` file with your actual values:
```bash
# Required
API_BASE_URL=your_live_endpoint
TEST_API_KEY=your_actual_test_api_key_here

# Optional (with defaults)
CHAT_MODELS=claude_3_5_sonnet,gemini-2.0-flash,llama3_8b
EMBEDDING_MODELS=cohere_english_v3,text-embedding-005
TEST_TIMEOUT=30
TEST_MAX_TOKENS=100
TEST_TEMPERATURE=0.1
```

### 3. Validate Configuration
```bash
python -c "from config import config; config.validate(); print('✅ Configuration valid!')"
```

### 4. Run Tests
```bash
# Run all integration tests
pytest -v

# Run specific test category
pytest 7_3_* -v  # Security tests
pytest 7_2_* -v  # Functional tests
```

## 📁 Test File Structure

```
tests/integration/
├── README.md                           # This file
├── MIGRATION_SUMMARY.md                # Complete migration documentation
├── config.py                           # Shared configuration module
├── requirements.txt                     # Python dependencies
├── .env.template                        # Environment configuration template
├── 7_2_EdgeCaseTesting.py              # Boundary and edge case tests
├── 7_2_FunctionalValidation.py         # Input validation tests
├── 7_2_ModelValidation.py              # Model capability tests
├── 7_3_1_OWASP_API2_Authentication.py  # Authentication security tests
├── 7_3_1_OWASP_API3_DataExposure.py    # Data exposure prevention tests
├── 7_3_2_LLM_PromptInjection.py        # LLM-specific security tests
├── 7_5_1_ErrorResponseValidation.py    # Error handling and sequences
├── 7_5_2_HTTPProtocolErrors.py         # HTTP protocol error tests
├── 7_5_3_ServerErrorHandling.py        # Server resilience tests
└── 7_9_DataPrivacyTesting.py           # Data privacy and PII tests
```

## 🧪 Test Categories

### Security Testing (7.3.x) - 3 Files
Tests aligned with OWASP API Security Top 10 (2023) and LLM-specific security concerns.

#### 7_3_1_OWASP_API2_Authentication.py
- **Purpose**: Authentication and authorization security testing
- **Coverage**: API key validation, timing attacks, brute force protection
- **Run**: `pytest 7_3_1_OWASP_API2_Authentication.py -v`

#### 7_3_1_OWASP_API3_DataExposure.py  
- **Purpose**: Data exposure and information leakage prevention
- **Coverage**: Response schema validation, cross-agency isolation
- **Run**: `pytest 7_3_1_OWASP_API3_DataExposure.py -v`

#### 7_3_2_LLM_PromptInjection.py
- **Purpose**: LLM-specific security vulnerabilities
- **Coverage**: Prompt injection, jailbreak attempts, encoding attacks
- **Run**: `pytest 7_3_2_LLM_PromptInjection.py -v`

### Functional Testing (7.2.x) - 3 Files
Tests for API functionality, input validation, and business logic.

#### 7_2_FunctionalValidation.py
- **Purpose**: Core API functionality and input validation
- **Coverage**: Schema compliance, parameter validation, capability matching
- **Run**: `pytest 7_2_FunctionalValidation.py -v`

#### 7_2_EdgeCaseTesting.py
- **Purpose**: Edge cases and boundary condition testing
- **Coverage**: Unicode handling, large payloads, parameter boundaries
- **Run**: `pytest 7_2_EdgeCaseTesting.py -v`

#### 7_2_ModelValidation.py
- **Purpose**: Model discovery and capability validation
- **Coverage**: Model routing, provider switching, capability mismatch
- **Run**: `pytest 7_2_ModelValidation.py -v`

### Reliability Testing (7.5.x) - 3 Files
Tests for error handling, resilience, and system reliability.

#### 7_5_1_ErrorResponseValidation.py
- **Purpose**: Error handling and API call sequences
- **Coverage**: Multi-turn conversations, concurrent requests, provider failover
- **Run**: `pytest 7_5_1_ErrorResponseValidation.py -v`

#### 7_5_2_HTTPProtocolErrors.py
- **Purpose**: HTTP protocol compliance and error handling
- **Coverage**: HTTP method validation, status codes, content types
- **Run**: `pytest 7_5_2_HTTPProtocolErrors.py -v`

#### 7_5_3_ServerErrorHandling.py
- **Purpose**: Server resilience and error recovery
- **Coverage**: Large payloads, concurrent load, malformed requests
- **Run**: `pytest 7_5_3_ServerErrorHandling.py -v`

### Data Privacy Testing (7.9.x) - 1 File
Tests for data privacy, anonymization, and PII handling.

#### 7_9_DataPrivacyTesting.py
- **Purpose**: Data privacy and anonymization validation
- **Coverage**: PII processing, cross-agency isolation, error message privacy
- **Run**: `pytest 7_9_DataPrivacyTesting.py -v`

## 🔧 Usage Examples

### Basic Test Execution
```bash
# Run all tests with verbose output
pytest -v

# Run tests with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest 7_3_1_OWASP_API2_Authentication.py -v

# Run specific test method
pytest 7_3_1_OWASP_API2_Authentication.py::TestOWASPAPI2Authentication::test_missing_auth_header -v
```

### Test Categories
```bash
# Security tests only
pytest 7_3_* -v

# Functional tests only  
pytest 7_2_* -v

# Reliability tests only
pytest 7_5_* -v

# Data privacy tests only
pytest 7_9_* -v
```

### Advanced Options
```bash
# Stop on first failure
pytest --maxfail=1

# Run tests in parallel (if pytest-xdist installed)
pytest -n auto

# Run with custom timeout
TEST_TIMEOUT=60 pytest 7_5_* -v

# Run against different environment
API_BASE_URL=https://staging.api.example.com/v1 pytest -v
```

## ⚙️ Configuration


### Configuration Validation
The test suite automatically validates configuration on startup:
```python
from config import config
config.validate()  # Raises error if required config missing
```

## 🔒 Security Considerations

### API Key Management
- ✅ API keys stored in `.env` file (not in code)
- ✅ `.env` file should be in `.gitignore`
- ✅ Use separate API keys for different environments
- ✅ Rotate API keys regularly

### Test Data Safety
- ✅ All test data is synthetic and benign
- ✅ No real PII or sensitive information used
- ✅ Tests designed to be safe in any environment
- ✅ Proper cleanup after test execution

### Network Security
- ✅ Tests require HTTPS endpoints only
- ✅ Certificate validation enabled
- ✅ No credentials logged or exposed

## 📊 Test Execution Guidelines

### Prerequisites
1. **Python Environment**: Python 3.8+ installed
2. **Virtual Environment**: Activated virtual environment (recommended)
3. **Network Access**: Ensure connectivity to the API endpoint
4. **Valid Credentials**: Have a valid API key with required scopes

### Best Practices
1. **Environment Isolation**: Use separate test environments
2. **Rate Limiting**: Be aware of API rate limits
3. **Cost Management**: Monitor API usage costs
4. **Parallel Execution**: Limit concurrent tests to avoid rate limits

### Expected Behavior
- **Success Rate**: >95% tests should pass in healthy environment
- **Execution Time**: Most tests complete within 30 seconds
- **Rate Limits**: Tests handle 429 responses gracefully
- **Error Handling**: Proper error messages for configuration issues

## 🐛 Troubleshooting

### Common Issues

#### Configuration Errors
```bash
# Issue: "TEST_API_KEY environment variable not set"
# Solution: Create .env file with valid API key
cp .env.template .env
# Edit .env with actual credentials
```

#### Network Connectivity
```bash
# Test connectivity manually
curl -H "Authorization: Bearer $TEST_API_KEY" $API_BASE_URL/models

# Check firewall/VPN settings
ping api.dev.aigov.mcaas.fcs.gsa.gov
```

#### Rate Limiting
```bash
# Issue: Getting 429 errors
# Solution: Reduce concurrent tests or add delays
pytest --maxfail=5 -v  # Stop on repeated failures
```

#### Timeout Issues
```bash
# Issue: Tests timing out
# Solution: Increase timeout value
TEST_TIMEOUT=60 pytest 7_5_* -v
```

### Debug Mode
```bash
# Run single test with full output
pytest 7_3_1_OWASP_API2_Authentication.py::TestOWASPAPI2Authentication::test_missing_auth_header -v -s

# Show configuration values
python -c "from config import config; print(f'URL: {config.BASE_URL}'); print(f'Timeout: {config.TIMEOUT}')"

# Test configuration validation
python -c "from config import config; config.validate(); print('Config OK')"
```

### Log Analysis
```bash
# Run with pytest logging
pytest --log-cli-level=DEBUG -v

# Capture HTTP traffic (if using httpx with logging)
HTTPX_LOG_LEVEL=DEBUG pytest -v -s
```

## 📈 Performance Considerations

### Execution Time
- **Individual Tests**: 1-5 seconds typical
- **Full Suite**: 5-15 minutes depending on network
- **Concurrent Execution**: Use with caution due to rate limits

### Resource Usage
- **Memory**: Minimal, tests are stateless
- **Network**: ~1-10 KB per request
- **API Costs**: Minimal token usage per test

### Optimization Tips
1. **Parallel Execution**: Use `pytest-xdist` with limited workers
2. **Test Selection**: Run relevant subsets during development
3. **Mock Fallback**: Consider hybrid approach for CI/CD
4. **Caching**: Cache model lists and static responses

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Integration Tests
on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          cd tests/integration
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt
      
      - name: Run integration tests
        env:
          API_BASE_URL: ${{ secrets.TEST_API_BASE_URL }}
          TEST_API_KEY: ${{ secrets.TEST_API_KEY }}
        run: |
          cd tests/integration
          source venv/bin/activate
          pytest -v --maxfail=5
```

### Environment-Specific Configs
```bash
# Development
cp .env.template .env.dev
# Edit with dev environment values

# Staging  
cp .env.template .env.staging
# Edit with staging environment values

# Production (read-only tests)
cp .env.template .env.prod
# Edit with production environment values
```

## 📚 Additional Resources

### External References
- [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/)
- [NIST SP 800-228](https://csrc.nist.gov/publications/detail/sp/800-228/draft)
- [httpx Documentation](https://www.python-httpx.org/)
- [pytest Documentation](https://docs.pytest.org/)

### Adding New Tests
1. **Choose appropriate file** based on TestPlan.md section
2. **Follow naming convention**: `test_descriptive_name`
3. **Use configuration module**: Import from `config`
4. **Add proper documentation**: Docstrings with expected behavior
5. **Handle errors gracefully**: Expect real API variations

### Test Pattern Example
```python
def test_new_security_feature(self, http_client: httpx.Client, auth_headers: Dict[str, str]):
    """
    Test description with expected behavior.
    
    Expected: Clear description of what should happen.
    """
    payload = {
        "model": config.get_chat_model(),
        "messages": [{"role": "user", "content": "test"}],
        "max_tokens": config.MAX_TOKENS
    }
    
    response = http_client.post(f"{config.BASE_URL}/chat/completions", 
                               json=payload, headers=auth_headers)
    
    assert response.status_code == 200
    # Add specific validations
```