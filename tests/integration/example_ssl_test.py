"""Example test demonstrating SSL configuration usage"""

import pytest
import os
from config import config
from utils import create_httpx_client, create_async_httpx_client


def test_ssl_configuration_sync():
    """Example of using SSL configuration with sync client"""
    # The client will automatically use SSL configuration from environment
    with create_httpx_client(base_url=config.BASE_URL, timeout=config.TIMEOUT) as client:
        # This will respect VERIFY_SSL and SSL_CERT_PATH settings
        response = client.get("/api/v1/models", headers=config.get_auth_headers())
        
        # Verify we can connect
        assert response.status_code in [200, 401, 403], f"Unexpected status: {response.status_code}"
        
        # Log SSL status for debugging
        if os.getenv('VERIFY_SSL', 'true').lower() == 'false':
            print("WARNING: SSL verification is disabled!")


@pytest.mark.asyncio
async def test_ssl_configuration_async(http_client):
    """Example of using SSL configuration with async client (uses fixture)"""
    # The http_client fixture already has SSL configuration applied
    response = await http_client.get("/api/v1/models", headers=config.get_auth_headers())
    
    # Verify we can connect
    assert response.status_code in [200, 401, 403], f"Unexpected status: {response.status_code}"


def test_quick_ssl_request():
    """Example of quick requests with SSL configuration"""
    from utils import get
    
    # This automatically uses SSL configuration
    response = get(
        f"{config.BASE_URL}/api/v1/models",
        headers=config.get_auth_headers()
    )
    
    assert response.status_code in [200, 401, 403], f"Unexpected status: {response.status_code}"


if __name__ == "__main__":
    # Quick test to verify SSL configuration
    print(f"SSL Verification: {os.getenv('VERIFY_SSL', 'true')}")
    print(f"SSL Certificate Path: {os.getenv('SSL_CERT_PATH', 'Not set')}")
    
    # Run the sync test
    test_ssl_configuration_sync()
    print("✅ SSL configuration test passed!")