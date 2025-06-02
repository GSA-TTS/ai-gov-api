# Enhanced Global Configuration and Fixtures for GSAi API Testing Framework
import pytest
import httpx
import asyncio
import logging
from typing import AsyncGenerator, Dict, Any, List
from pathlib import Path

from config import config, cost_tracker, logger
from fixtures.auth_fixtures import AuthFixtures
from fixtures.multimodal_fixtures import MultiModalFixtures
from fixtures.security_fixtures import SecurityFixtures
from utils.cost_tracking import CostTracker
from utils.security_validators import SecurityValidator


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an HTTP client for testing"""
    config.validate()
    
    async with httpx.AsyncClient(
        base_url=config.BASE_URL,
        timeout=config.TIMEOUT,
        headers={"User-Agent": "GSAi-API-Test-Framework/1.0"}
    ) as client:
        yield client


@pytest.fixture(scope="session")
def auth_headers() -> Dict[str, str]:
    """Get default authentication headers"""
    return config.get_auth_headers()


@pytest.fixture(scope="session")
def admin_auth_headers() -> Dict[str, str]:
    """Get admin authentication headers"""
    return config.get_auth_headers('admin')


@pytest.fixture(scope="session")
def embedding_auth_headers() -> Dict[str, str]:
    """Get embedding authentication headers"""
    return config.get_auth_headers('embedding')


@pytest.fixture(scope="function")
def cost_tracking():
    """Reset cost tracking for each test"""
    cost_tracker.total_cost = 0.0
    cost_tracker.total_tokens = 0
    cost_tracker.request_count = 0
    return cost_tracker


@pytest.fixture(scope="session")
def auth_fixtures():
    """Authentication test fixtures"""
    return AuthFixtures()


@pytest.fixture(scope="session")
def multimodal_fixtures():
    """Multi-modal test fixtures"""
    return MultiModalFixtures()


@pytest.fixture(scope="session")
def security_fixtures():
    """Security test fixtures"""
    return SecurityFixtures()


@pytest.fixture(scope="session")
def security_validator():
    """Security validation utilities"""
    return SecurityValidator()


@pytest.fixture(scope="function")
def chat_request_basic():
    """Basic chat completion request"""
    return {
        "model": config.get_chat_model(0),
        "messages": [
            {"role": "user", "content": "Hello, this is a test message."}
        ],
        "max_tokens": config.MAX_TOKENS,
        "temperature": config.TEMPERATURE
    }


@pytest.fixture(scope="function")
def embedding_request_basic():
    """Basic embedding request"""
    return {
        "model": config.get_embedding_model(0),
        "input": "This is a test sentence for embedding."
    }


@pytest.fixture(scope="function")
def models_endpoint():
    """Models endpoint URL"""
    return "/api/v1/models"


@pytest.fixture(scope="function")
def chat_endpoint():
    """Chat completions endpoint URL"""
    return "/api/v1/chat/completions"


@pytest.fixture(scope="function")
def embeddings_endpoint():
    """Embeddings endpoint URL"""
    return "/api/v1/embeddings"


@pytest.fixture(scope="session")
def test_data_dir():
    """Test data directory path"""
    return Path(__file__).parent / "test_data"


@pytest.fixture(autouse=True)
def skip_if_disabled(request):
    """Automatically skip tests based on configuration"""
    test_name = request.node.name.lower()
    
    # Skip security tests if disabled
    if 'security' in test_name and not config.should_run_security_tests():
        pytest.skip("Security tests disabled")
    
    # Skip zero trust tests if disabled
    if 'zero_trust' in test_name and not config.should_run_zero_trust_tests():
        pytest.skip("Zero Trust tests disabled")
    
    # Skip prompt injection tests if disabled
    if 'prompt_injection' in test_name and not config.should_run_prompt_injection_tests():
        pytest.skip("Prompt injection tests disabled")
    
    # Skip load tests if disabled
    if 'load' in test_name and not config.should_run_load_tests():
        pytest.skip("Load tests disabled")


def pytest_configure(config_obj):
    """Configure pytest with custom markers"""
    config_obj.addinivalue_line(
        "markers", "security: mark test as a security test"
    )
    config_obj.addinivalue_line(
        "markers", "zero_trust: mark test as a zero trust test"
    )
    config_obj.addinivalue_line(
        "markers", "prompt_injection: mark test as a prompt injection test"
    )
    config_obj.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config_obj.addinivalue_line(
        "markers", "reliability: mark test as a reliability test"
    )
    config_obj.addinivalue_line(
        "markers", "data_management: mark test as a data management test"
    )
    config_obj.addinivalue_line(
        "markers", "functional: mark test as a functional test"
    )
    config_obj.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_sessionstart(session):
    """Initialize testing session"""
    logger.info("Starting GSAi API Testing Framework")
    logger.info(f"Base URL: {config.BASE_URL}")
    logger.info(f"Cost tracking enabled: {config.ENABLE_COST_TRACKING}")
    logger.info(f"Daily budget: ${config.DAILY_BUDGET}")


def pytest_sessionfinish(session, exitstatus):
    """Cleanup and report after testing session"""
    summary = cost_tracker.get_summary()
    logger.info("Testing session completed")
    logger.info(f"Total cost: ${summary['total_cost']:.2f}")
    logger.info(f"Total tokens: {summary['total_tokens']}")
    logger.info(f"Total requests: {summary['request_count']}")
    logger.info(f"Average cost per request: ${summary['avg_cost_per_request']:.4f}")


def pytest_runtest_logstart(nodeid, location):
    """Log test start"""
    if config.ENABLE_REQUEST_LOGGING:
        logger.debug(f"Starting test: {nodeid}")


def pytest_runtest_logfinish(nodeid, location):
    """Log test completion"""
    if config.ENABLE_REQUEST_LOGGING:
        logger.debug(f"Finished test: {nodeid}")


@pytest.fixture(scope="function")
async def make_request():
    """Helper fixture for making API requests with cost tracking"""
    async def _make_request(client: httpx.AsyncClient, method: str, url: str, 
                           headers: Dict[str, str], data: Dict[str, Any] = None,
                           track_cost: bool = True, expected_tokens: int = 50):
        """Make an API request with optional cost tracking"""
        if track_cost:
            # Estimate tokens for cost tracking (this is a rough estimate)
            if data and 'messages' in data:
                estimated_input_tokens = sum(len(msg.get('content', '')) // 4 for msg in data['messages'])
            elif data and 'input' in data:
                estimated_input_tokens = len(str(data['input'])) // 4
            else:
                estimated_input_tokens = expected_tokens
            
            cost_tracker.add_request(estimated_input_tokens, expected_tokens)
        
        if config.ENABLE_REQUEST_LOGGING:
            logger.debug(f"{method} {url}")
            if config.ENABLE_RESPONSE_LOGGING and data:
                logger.debug(f"Request data: {data}")
        
        if method.upper() == "GET":
            response = await client.get(url, headers=headers)
        elif method.upper() == "POST":
            response = await client.post(url, headers=headers, json=data)
        elif method.upper() == "PUT":
            response = await client.put(url, headers=headers, json=data)
        elif method.upper() == "DELETE":
            response = await client.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        if config.ENABLE_RESPONSE_LOGGING:
            logger.debug(f"Response status: {response.status_code}")
            if response.status_code >= 400:
                logger.debug(f"Response body: {response.text}")
        
        return response
    
    return _make_request