# tests/integration/conftest.py
import pytest
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Tuple, List

# Assuming your project root is one level up from the 'tests' directory
# If your 'tests' directory is at the root, adjust as needed.
# This is to ensure 'app' can be imported.
# import sys
# PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
# sys.path.insert(0, PROJECT_ROOT)

# If running tests from project root (e.g. `uv run pytest`), direct imports should work.
from app.auth.utils import generate_api_key
from app.db.session import get_db_session, async_session
from app.users.models import User
from app.auth.models import APIKey as APIKeyModel
from app.auth.schemas import Role, Scope as AuthScope

# Configuration
BASE_URL = os.getenv("TEST_BASE_URL", "http://127.0.0.1:8000/api/v1") # Allow overriding via env var

# --- Helper Functions for DB Setup ---
async def create_user_in_db(email: str, name: str, role: Role) -> User:
    async with async_session() as session:
        async with session.begin():
            db_user = User(email=email, name=name, role=role.value, is_active=True)
            session.add(db_user)
            await session.flush() # Use flush to get ID before commit
            await session.refresh(db_user)
            await session.commit() # Commit after refresh if needed, or rely on outer commit
            return db_user

async def create_api_key_in_db(
    user_id: uuid.UUID,
    key_prefix: str,
    scopes: List[AuthScope],
    is_active: bool = True,
    expires_at: datetime = None
) -> Tuple[str, APIKeyModel]:
    raw_key, hashed_key = generate_api_key(prefix=key_prefix)
    async with async_session() as session:
        async with session.begin():
            db_api_key = APIKeyModel(
                manager_id=user_id,
                hashed_key=hashed_key,
                key_prefix=key_prefix,
                scopes=[s.value for s in scopes],
                is_active=is_active,
                expires_at=expires_at
            )
            session.add(db_api_key)
            await session.flush()
            await session.refresh(db_api_key)
            await session.commit()
            return raw_key, db_api_key

# --- Fixtures ---

@pytest.fixture(scope="session")
def event_loop():
    """
    pytest-asyncio provides an event_loop fixture, but if you need to customize it
    or ensure it's the one from asyncio, you can define it.
    Often, pytest-asyncio's default is fine.
    """
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def test_user() -> User:
    """Creates a standard test user in the database for the module."""
    return await create_user_in_db(f"testuser_{uuid.uuid4()}@example.com", "Test User", Role.USER)

@pytest.fixture
async def valid_api_key_all_scopes(test_user: User) -> str:
    """Provides a valid, active, non-expired API key string with all relevant scopes."""
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_all",
        scopes=[AuthScope.MODELS_INFERENCE, AuthScope.MODELS_EMBEDDING]
    )
    return raw_key

@pytest.fixture
async def valid_api_key_inference_only(test_user: User) -> str:
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_inf",
        scopes=[AuthScope.MODELS_INFERENCE]
    )
    return raw_key

@pytest.fixture
async def valid_api_key_embedding_only(test_user: User) -> str:
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_emb",
        scopes=[AuthScope.MODELS_EMBEDDING]
    )
    return raw_key

@pytest.fixture
async def valid_api_key_no_scopes(test_user: User) -> str:
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_none",
        scopes=[]
    )
    return raw_key

@pytest.fixture
async def inactive_api_key(test_user: User) -> str:
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_inactive",
        scopes=[AuthScope.MODELS_INFERENCE],
        is_active=False
    )
    return raw_key

@pytest.fixture
async def expired_api_key(test_user: User) -> str:
    raw_key, _ = await create_api_key_in_db(
        user_id=test_user.id,
        key_prefix="test_expired",
        scopes=[AuthScope.MODELS_INFERENCE],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    return raw_key

@pytest.fixture
def valid_headers(valid_api_key_all_scopes: str) -> Dict[str, str]:
    """Provides valid authorization headers."""
    return {
        "Authorization": f"Bearer {valid_api_key_all_scopes}",
        "Content-Type": "application/json"
    }

@pytest.fixture
def minimal_chat_payload() -> Dict[str, Any]:
    # Use a model ID that you expect to be configured and have 'chat' capability
    # This might need to be adjusted based on your actual settings.backend_map
    # For testing, we assume "claude_3_5_sonnet" is a valid chat model ID.
    return {
        "model": "claude_3_5_sonnet", # Or "gemini-2.0-flash" if that's preferred/available
        "messages": [{"role": "user", "content": "Hello"}]
    }

@pytest.fixture
def minimal_embedding_payload() -> Dict[str, Any]:
    # Assume "cohere_english_v3" is a valid embedding model ID.
    return {
        "model": "cohere_english_v3", # Or "text-embedding-005"
        "input": "This is a test sentence."
    }

# Fixture for a chat model ID known to be configured
@pytest.fixture
def configured_chat_model_id() -> str:
    # This should match an ID in your app.config.settings.Settings.backend_map
    # that has 'chat' capability.
    return "claude_3_5_sonnet" # Example, adjust as per your actual settings

# Fixture for an embedding model ID known to be configured
@pytest.fixture
def configured_embedding_model_id() -> str:
    # This should match an ID in your app.config.settings.Settings.backend_map
    # that has 'embedding' capability.
    return "cohere_english_v3" # Example, adjust as per your actual settings

# Fixture for an image data URI (valid format, dummy data)
@pytest.fixture
def valid_image_data_uri() -> str:
    # A minimal valid base64 for a tiny transparent PNG
    return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

# Fixture for a file data (valid base64, dummy PDF-like data)
@pytest.fixture
def valid_file_data_base64() -> str:
    # This is not a real PDF, just valid base64. For real tests, use a tiny valid PDF.
    # base64.b64encode(b"%PDF-1.4\n%test\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 35 >>\nstream\nBT /F1 24 Tf 100 700 Td (Hello) Tj ET\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF").decode('utf-8')
    return "JVBERi0xLjQKJXRlc3QKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUiIgL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCA2MTIgNzkyXSAvQ29udGVudHMgNCAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAzNSAA+Pgpic3RyZWFtCkJUL0YxIDI0IFRmIDEwMCA3MDAgVGQgKEhlbGxvKSBUaiBFVAplbmRzdHJlYW0KZW5kb2JqCnRyYWlsZXIKPDwgL1Jvb3QgMSAwIFIgPj4KJSVFT0Y="

