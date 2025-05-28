# tests/integration/config.py
# Shared configuration for integration tests

import os
from pathlib import Path
from typing import List, Dict, Any
import pytest

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    # dotenv not available, use system environment variables
    pass


class TestConfig:
    """Configuration class for integration tests"""
    
    # API Configuration
    BASE_URL: str = os.getenv('API_BASE_URL','')
    API_KEY: str = os.getenv('TEST_API_KEY', '')
    
    # Model Configuration
    CHAT_MODELS: List[str] = os.getenv('CHAT_MODELS', 'claude_3_5_sonnet,gemini-2.0-flash,llama3_8b').split(',')
    EMBEDDING_MODELS: List[str] = os.getenv('EMBEDDING_MODELS', 'cohere_english_v3,text-embedding-005').split(',')
    
    # Test Configuration
    TIMEOUT: int = int(os.getenv('TEST_TIMEOUT', '30'))
    MAX_TOKENS: int = int(os.getenv('TEST_MAX_TOKENS', '100'))
    TEMPERATURE: float = float(os.getenv('TEST_TEMPERATURE', '0.1'))
    
    # Provider Configuration
    AWS_REGION: str = os.getenv('AWS_REGION', 'us-east-1')
    GCP_PROJECT_ID: str = os.getenv('GCP_PROJECT_ID', '')
    
    @classmethod
    def validate(cls) -> None:
        """Validate required configuration"""
        if not cls.API_KEY:
            pytest.skip("TEST_API_KEY environment variable not set")
        
        if not cls.BASE_URL:
            pytest.skip("API_BASE_URL environment variable not set")
    
    @classmethod
    def get_auth_headers(cls) -> Dict[str, str]:
        """Get authentication headers"""
        cls.validate()
        return {
            "Authorization": f"Bearer {cls.API_KEY}",
            "Content-Type": "application/json"
        }
    
    @classmethod
    def get_chat_model(cls, index: int = 0) -> str:
        """Get chat model by index"""
        if index >= len(cls.CHAT_MODELS):
            pytest.skip(f"Chat model index {index} not available")
        return cls.CHAT_MODELS[index]
    
    @classmethod
    def get_embedding_model(cls, index: int = 0) -> str:
        """Get embedding model by index"""
        if index >= len(cls.EMBEDDING_MODELS):
            pytest.skip(f"Embedding model index {index} not available")
        return cls.EMBEDDING_MODELS[index]


# Global configuration instance
config = TestConfig