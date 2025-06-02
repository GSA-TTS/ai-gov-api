# Authentication Fixtures for GSAi API Testing Framework
import secrets
import string
import sys
from typing import Dict, List, Any
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config


class AuthFixtures:
    """Fixtures for authentication and authorization testing"""
    
    def __init__(self):
        self.invalid_keys = self._generate_invalid_keys()
        self.malformed_headers = self._generate_malformed_headers()
    
    def _generate_invalid_keys(self) -> List[str]:
        """Generate various invalid API keys for testing"""
        return [
            "invalid_key_123",
            "bearer_token_456",
            "api_key_789",
            "",
            " ",
            "null",
            "undefined",
            "x" * 100,  # Too long
            "short",     # Too short
            "key with spaces",
            "key@with#special$chars",
            "12345",     # Numeric only
            "ABCDEF",    # Letters only
            secrets.token_urlsafe(32),  # Valid format but non-existent
        ]
    
    def _generate_malformed_headers(self) -> List[Dict[str, str]]:
        """Generate malformed authorization headers"""
        return [
            {},  # No authorization header
            {"Authorization": ""},  # Empty authorization
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "Token invalid_token"},  # Wrong scheme
            {"Authorization": "Basic invalid_token"},  # Wrong scheme
            {"Authorization": f"Bearer {config.API_KEY} extra"},  # Extra data
            {"Authorization": f"bearer {config.API_KEY}"},  # Wrong case
            {"authorization": f"Bearer {config.API_KEY}"},  # Wrong case header
            {"Auth": f"Bearer {config.API_KEY}"},  # Wrong header name
            {"X-API-Key": config.API_KEY},  # Wrong header format
        ]
    
    def get_valid_headers(self, key_type: str = 'default') -> Dict[str, str]:
        """Get valid authentication headers"""
        return config.get_auth_headers(key_type)
    
    def get_invalid_key_headers(self, index: int = 0) -> Dict[str, str]:
        """Get headers with invalid API key"""
        if index >= len(self.invalid_keys):
            index = 0
        return {
            "Authorization": f"Bearer {self.invalid_keys[index]}",
            "Content-Type": "application/json"
        }
    
    def get_malformed_header(self, index: int = 0) -> Dict[str, str]:
        """Get malformed authorization header"""
        if index >= len(self.malformed_headers):
            index = 0
        base_headers = {"Content-Type": "application/json"}
        base_headers.update(self.malformed_headers[index])
        return base_headers
    
    def get_expired_key_simulation(self) -> Dict[str, str]:
        """Simulate expired key (for testing purposes)"""
        # This would need to be coordinated with actual expired keys in the system
        return {
            "Authorization": "Bearer expired_key_simulation",
            "Content-Type": "application/json"
        }
    
    def get_inactive_key_simulation(self) -> Dict[str, str]:
        """Simulate inactive key (for testing purposes)"""
        # This would need to be coordinated with actual inactive keys in the system
        return {
            "Authorization": "Bearer inactive_key_simulation",
            "Content-Type": "application/json"
        }
    
    def generate_scope_test_combinations(self) -> List[Dict[str, Any]]:
        """Generate test combinations for scope testing"""
        return [
            {
                "description": "Valid inference scope",
                "headers": self.get_valid_headers('default'),
                "expected_endpoints": ["/api/v1/chat/completions"],
                "blocked_endpoints": []
            },
            {
                "description": "Valid embedding scope", 
                "headers": self.get_valid_headers('embedding'),
                "expected_endpoints": ["/api/v1/embeddings"],
                "blocked_endpoints": ["/api/v1/chat/completions"]
            },
            {
                "description": "Admin scope",
                "headers": self.get_valid_headers('admin'),
                "expected_endpoints": ["/api/v1/models", "/api/v1/chat/completions"],
                "blocked_endpoints": []
            }
        ]
    
    def get_brute_force_test_keys(self, count: int = 100) -> List[str]:
        """Generate keys for brute force testing"""
        keys = []
        for i in range(count):
            # Generate realistic but invalid API keys
            key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            keys.append(f"test_prefix_{key}")
        return keys
    
    def get_timing_attack_keys(self) -> List[str]:
        """Generate keys for timing attack testing"""
        return [
            config.API_KEY[:-1] + "x",  # One character different
            config.API_KEY[:-2] + "xx",  # Two characters different  
            config.API_KEY[:10] + "x" * (len(config.API_KEY) - 10),  # Different suffix
            "x" * len(config.API_KEY),  # Same length, all different
            config.API_KEY + "x",  # Extra character
            config.API_KEY[1:],  # Missing first character
        ]