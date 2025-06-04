# Enhanced Configuration for GSAi API Testing Framework
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import pytest

# Load environment variables from .env file if it exists
# Using built-in configparser instead of python-dotenv
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    # Read .env file manually
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value


@dataclass
class TestConfig:
    """Enhanced configuration class for comprehensive testing"""
    
    # ===== CORE API CONFIGURATION =====
    BASE_URL: str = os.getenv('API_BASE_URL', '')
    API_KEY: str = os.getenv('TEST_API_KEY', '')
    ADMIN_API_KEY: str = os.getenv('TEST_ADMIN_API_KEY', '')
    EMBEDDING_API_KEY: str = os.getenv('TEST_EMBEDDING_API_KEY', '')
    
    # ===== MODEL CONFIGURATION =====
    CHAT_MODELS: List[str] = None
    EMBEDDING_MODELS: List[str] = None
    
    # ===== PROVIDER CONFIGURATION =====
    AWS_REGION: str = os.getenv('AWS_REGION', 'us-east-1')
    GCP_PROJECT_ID: str = os.getenv('GCP_PROJECT_ID', '')
    
    # ===== TEST EXECUTION CONFIGURATION =====
    TIMEOUT: int = int(os.getenv('TEST_TIMEOUT', '30'))
    MAX_TOKENS: int = int(os.getenv('TEST_MAX_TOKENS', '100'))
    TEMPERATURE: float = float(os.getenv('TEST_TEMPERATURE', '0.1'))
    PARALLEL_WORKERS: int = int(os.getenv('PARALLEL_WORKERS', '4'))
    
    # ===== COST MANAGEMENT =====
    DAILY_BUDGET: float = float(os.getenv('DAILY_TEST_BUDGET', '50.0'))
    COST_PER_1K_TOKENS: float = float(os.getenv('COST_PER_1K_TOKENS', '0.01'))
    ENABLE_COST_TRACKING: bool = os.getenv('ENABLE_COST_TRACKING', 'true').lower() == 'true'
    
    # ===== SECURITY TESTING =====
    ENABLE_SECURITY_TESTS: bool = os.getenv('ENABLE_SECURITY_TESTS', 'true').lower() == 'true'
    ENABLE_ZERO_TRUST_TESTS: bool = os.getenv('ENABLE_ZERO_TRUST_TESTS', 'true').lower() == 'true'
    ENABLE_PROMPT_INJECTION_TESTS: bool = os.getenv('ENABLE_PROMPT_INJECTION_TESTS', 'true').lower() == 'true'
    SECURITY_TEST_TIMEOUT: int = int(os.getenv('SECURITY_TEST_TIMEOUT', '60'))
    
    # ===== MULTI-MODAL TESTING =====
    MAX_FILE_SIZE_MB: int = int(os.getenv('MAX_FILE_SIZE_MB', '10'))
    SUPPORTED_FILE_TYPES: List[str] = None
    FILE_PROCESSING_TIMEOUT: int = int(os.getenv('FILE_PROCESSING_TIMEOUT', '30'))
    ENABLE_MALICIOUS_FILE_TESTS: bool = os.getenv('ENABLE_MALICIOUS_FILE_TESTS', 'false').lower() == 'true'
    
    # ===== DATA MANAGEMENT =====
    ENABLE_DATA_GENERATION_TESTS: bool = os.getenv('ENABLE_DATA_GENERATION_TESTS', 'true').lower() == 'true'
    SYNTHETIC_DATA_ENABLED: bool = os.getenv('SYNTHETIC_DATA_ENABLED', 'true').lower() == 'true'
    DATA_RETENTION_DAYS: int = int(os.getenv('DATA_RETENTION_DAYS', '30'))
    
    # ===== PERFORMANCE TESTING =====
    LOAD_TEST_ENABLED: bool = os.getenv('LOAD_TEST_ENABLED', 'false').lower() == 'true'
    LOAD_TEST_CONCURRENT_USERS: int = int(os.getenv('LOAD_TEST_CONCURRENT_USERS', '10'))
    LOAD_TEST_DURATION: int = int(os.getenv('LOAD_TEST_DURATION_SECONDS', '60'))
    
    # ===== RELIABILITY TESTING =====
    CIRCUIT_BREAKER_ENABLED: bool = os.getenv('CIRCUIT_BREAKER_ENABLED', 'true').lower() == 'true'
    RETRY_MAX_ATTEMPTS: int = int(os.getenv('RETRY_MAX_ATTEMPTS', '3'))
    RETRY_BACKOFF_SECONDS: int = int(os.getenv('RETRY_BACKOFF_SECONDS', '1'))
    
    # ===== LOGGING AND MONITORING =====
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    ENABLE_REQUEST_LOGGING: bool = os.getenv('ENABLE_REQUEST_LOGGING', 'true').lower() == 'true'
    ENABLE_RESPONSE_LOGGING: bool = os.getenv('ENABLE_RESPONSE_LOGGING', 'false').lower() == 'true'
    METRICS_ENABLED: bool = os.getenv('METRICS_ENABLED', 'true').lower() == 'true'
    
    def __post_init__(self):
        """Initialize derived attributes"""
        if self.CHAT_MODELS is None:
            self.CHAT_MODELS = os.getenv('CHAT_MODELS', 'claude_3_5_sonnet,gemini-2.0-flash,llama3_8b').split(',')
        if self.EMBEDDING_MODELS is None:
            self.EMBEDDING_MODELS = os.getenv('EMBEDDING_MODELS', 'cohere_english_v3,text-embedding-005').split(',')
        if self.SUPPORTED_FILE_TYPES is None:
            self.SUPPORTED_FILE_TYPES = os.getenv('SUPPORTED_FILE_TYPES', 'jpeg,png,pdf,txt').split(',')
    
    def validate(self) -> None:
        """Validate required configuration"""
        if not self.API_KEY:
            pytest.skip("TEST_API_KEY environment variable not set")
        
        if not self.BASE_URL:
            pytest.skip("API_BASE_URL environment variable not set")
    
    def validate_admin_access(self) -> None:
        """Validate admin API key is available"""
        if not self.ADMIN_API_KEY:
            pytest.skip("TEST_ADMIN_API_KEY environment variable not set for admin tests")
    
    def validate_embedding_access(self) -> None:
        """Validate embedding API key is available"""
        if not self.EMBEDDING_API_KEY:
            pytest.skip("TEST_EMBEDDING_API_KEY environment variable not set for embedding tests")
    
    def get_auth_headers(self, key_type: str = 'default') -> Dict[str, str]:
        """Get authentication headers for different key types"""
        self.validate()
        
        if key_type == 'admin':
            self.validate_admin_access()
            api_key = self.ADMIN_API_KEY
        elif key_type == 'embedding':
            self.validate_embedding_access()
            api_key = self.EMBEDDING_API_KEY
        else:
            api_key = self.API_KEY
        
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def get_chat_model(self, index: int = 0) -> str:
        """Get chat model by index"""
        if index >= len(self.CHAT_MODELS):
            pytest.skip(f"Chat model index {index} not available")
        return self.CHAT_MODELS[index].strip()
    
    def get_embedding_model(self, index: int = 0) -> str:
        """Get embedding model by index"""
        if index >= len(self.EMBEDDING_MODELS):
            pytest.skip(f"Embedding model index {index} not available")
        return self.EMBEDDING_MODELS[index].strip()
    
    def should_run_security_tests(self) -> bool:
        """Check if security tests should run"""
        return self.ENABLE_SECURITY_TESTS
    
    def should_run_zero_trust_tests(self) -> bool:
        """Check if zero trust tests should run"""
        return self.ENABLE_ZERO_TRUST_TESTS
    
    def should_run_prompt_injection_tests(self) -> bool:
        """Check if prompt injection tests should run"""
        return self.ENABLE_PROMPT_INJECTION_TESTS
    
    def should_run_load_tests(self) -> bool:
        """Check if load tests should run"""
        return self.LOAD_TEST_ENABLED
    
    def get_supported_file_types(self) -> List[str]:
        """Get list of supported file types for testing"""
        return [ft.strip() for ft in self.SUPPORTED_FILE_TYPES]


# Global configuration instance
config = TestConfig()

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class CostTracker:
    """Track API costs during testing"""
    
    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.request_count = 0
    
    def add_request(self, input_tokens: int, output_tokens: int = 0):
        """Add a request to cost tracking"""
        total_tokens = input_tokens + output_tokens
        cost = (total_tokens / 1000) * config.COST_PER_1K_TOKENS
        
        self.total_tokens += total_tokens
        self.total_cost += cost
        self.request_count += 1
        
        if config.ENABLE_COST_TRACKING and self.total_cost > config.DAILY_BUDGET:
            pytest.skip(f"Daily budget exceeded: ${self.total_cost:.2f} > ${config.DAILY_BUDGET}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get cost tracking summary"""
        return {
            "total_cost": self.total_cost,
            "total_tokens": self.total_tokens,
            "request_count": self.request_count,
            "avg_cost_per_request": self.total_cost / max(1, self.request_count)
        }


# Global cost tracker
cost_tracker = CostTracker()