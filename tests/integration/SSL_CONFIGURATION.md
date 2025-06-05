# SSL/TLS Configuration for Integration Tests

This document explains how to configure SSL/TLS verification for the integration test suite.

## Overview

The integration test suite now supports configurable SSL/TLS verification, allowing you to:
- Disable SSL verification for development/testing environments
- Use custom CA certificates for self-signed certificates
- Maintain secure defaults for production testing

## Configuration Options

### Environment Variables

1. **`VERIFY_SSL`** (default: `true`)
   - Set to `false` to disable SSL verification
   - **WARNING**: Only disable SSL verification in development/testing environments

   ```bash
   export VERIFY_SSL=false
   ```

2. **`SSL_CERT_PATH`** (default: none)
   - Path to a custom CA certificate file
   - Useful for testing against servers with self-signed certificates
   
   ```bash
   export SSL_CERT_PATH=/path/to/ca-cert.pem
   ```

## Usage Examples

### Running Tests with SSL Verification Disabled

```bash
# Disable SSL verification for all tests
VERIFY_SSL=false pytest tests/integration/

# Or export for the session
export VERIFY_SSL=false
pytest tests/integration/
```

### Running Tests with Custom CA Certificate

```bash
# Use custom certificate
SSL_CERT_PATH=/path/to/ca-cert.pem pytest tests/integration/
```

### Using in .env File

Create a `.env` file in the `tests/integration/` directory:

```env
# Disable SSL verification (development only!)
VERIFY_SSL=false

# Or use custom certificate
# SSL_CERT_PATH=/path/to/ca-cert.pem
```

## Implementation Details

### Automatic SSL Configuration

All test fixtures and utilities automatically respect the SSL configuration:

1. **`http_client` fixture** - AsyncClient with SSL config
2. **`ssl_config.create_httpx_client()`** - Sync client helper
3. **`ssl_config.create_async_httpx_client()`** - Async client helper

### Direct Usage in Tests

If you need to create an HTTP client directly in your tests:

```python
from tests.integration.utils.ssl_config import create_httpx_client, create_async_httpx_client

# Sync client
with create_httpx_client(timeout=30) as client:
    response = client.get("https://api.example.com/endpoint")

# Async client
async with create_async_httpx_client(timeout=30) as client:
    response = await client.get("https://api.example.com/endpoint")
```

### Quick Requests

For one-off requests:

```python
from tests.integration.utils.ssl_config import get, post

# These functions automatically use SSL configuration
response = get("https://api.example.com/endpoint")
response = post("https://api.example.com/endpoint", json={"key": "value"})
```

## Security Warnings

- **NEVER** disable SSL verification in production environments
- SSL verification is enabled by default for security
- A warning will be displayed if SSL verification is disabled
- Only use `VERIFY_SSL=false` when testing against development servers

## Troubleshooting

### Certificate Verification Failed

If you see SSL certificate verification errors:

1. **For self-signed certificates**: Export the CA certificate and use `SSL_CERT_PATH`
2. **For development servers**: Temporarily set `VERIFY_SSL=false`
3. **For production**: Ensure the server has valid SSL certificates

### Example Error:

```
httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```

**Solution**:
```bash
# For development only
VERIFY_SSL=false pytest tests/integration/test_file.py

# Or with custom cert
SSL_CERT_PATH=/path/to/server-ca.pem pytest tests/integration/test_file.py
```

## Best Practices

1. Always use SSL verification in production testing
2. Store custom certificates securely
3. Document any SSL configuration requirements for your test environment
4. Use environment-specific configuration files (.env.dev, .env.test, etc.)
5. Never commit `.env` files with `VERIFY_SSL=false` to version control