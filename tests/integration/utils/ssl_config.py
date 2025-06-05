"""SSL/TLS Configuration Helper for Integration Tests

This module provides utilities for configuring SSL verification across all test cases.
"""

import os
import httpx
from typing import Union, Optional
from pathlib import Path
import warnings


def get_ssl_verify_config() -> Union[bool, str]:
    """Get SSL verification configuration from environment variables.
    
    Returns:
        bool or str: Either a boolean flag for SSL verification or a path to a certificate file.
    """
    # Check for SSL certificate path first
    ssl_cert_path = os.getenv('SSL_CERT_PATH', None)
    if ssl_cert_path and Path(ssl_cert_path).exists():
        return ssl_cert_path
    
    # Otherwise use boolean flag
    verify_ssl = os.getenv('VERIFY_SSL', 'true').lower() == 'true'
    
    # Warn if SSL verification is disabled
    if not verify_ssl:
        warnings.warn(
            "SSL verification is disabled. This should only be used in development/testing environments.",
            RuntimeWarning,
            stacklevel=2
        )
    
    return verify_ssl


def create_httpx_client(base_url: Optional[str] = None, 
                       timeout: Optional[float] = None,
                       **kwargs) -> httpx.Client:
    """Create a synchronous httpx client with SSL configuration.
    
    Args:
        base_url: Base URL for the client
        timeout: Request timeout in seconds
        **kwargs: Additional arguments to pass to httpx.Client
        
    Returns:
        httpx.Client: Configured HTTP client
    """
    verify = get_ssl_verify_config()
    
    # Merge SSL config with any provided kwargs
    client_kwargs = {
        'verify': verify,
        **kwargs
    }
    
    if base_url:
        client_kwargs['base_url'] = base_url
    
    if timeout:
        client_kwargs['timeout'] = timeout
    
    return httpx.Client(**client_kwargs)


def create_async_httpx_client(base_url: Optional[str] = None,
                             timeout: Optional[float] = None,
                             **kwargs) -> httpx.AsyncClient:
    """Create an asynchronous httpx client with SSL configuration.
    
    Args:
        base_url: Base URL for the client
        timeout: Request timeout in seconds
        **kwargs: Additional arguments to pass to httpx.AsyncClient
        
    Returns:
        httpx.AsyncClient: Configured async HTTP client
    """
    verify = get_ssl_verify_config()
    
    # Merge SSL config with any provided kwargs
    client_kwargs = {
        'verify': verify,
        **kwargs
    }
    
    if base_url:
        client_kwargs['base_url'] = base_url
    
    if timeout:
        client_kwargs['timeout'] = timeout
    
    return httpx.AsyncClient(**client_kwargs)


# Convenience functions for quick requests with SSL config
def get(url: str, **kwargs) -> httpx.Response:
    """Make a GET request with SSL configuration."""
    verify = get_ssl_verify_config()
    return httpx.get(url, verify=verify, **kwargs)


def post(url: str, **kwargs) -> httpx.Response:
    """Make a POST request with SSL configuration."""
    verify = get_ssl_verify_config()
    return httpx.post(url, verify=verify, **kwargs)


def put(url: str, **kwargs) -> httpx.Response:
    """Make a PUT request with SSL configuration."""
    verify = get_ssl_verify_config()
    return httpx.put(url, verify=verify, **kwargs)


def delete(url: str, **kwargs) -> httpx.Response:
    """Make a DELETE request with SSL configuration."""
    verify = get_ssl_verify_config()
    return httpx.delete(url, verify=verify, **kwargs)


def patch(url: str, **kwargs) -> httpx.Response:
    """Make a PATCH request with SSL configuration."""
    verify = get_ssl_verify_config()
    return httpx.patch(url, verify=verify, **kwargs)