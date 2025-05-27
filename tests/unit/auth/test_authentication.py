# tests/test_auth.py

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock  

from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from app.auth.dependencies import valid_api_key
from app.auth.schemas import APIKeyOut
from app.auth.models import APIKey



API_KEY_REPOSITORY_PATH = "app.auth.dependencies.APIKeyRepository" 
pytestmark = pytest.mark.asyncio

@pytest.fixture(scope="module") 
def api_key() -> HTTPAuthorizationCredentials:
    # the unit under test does not validate the api key
    # but we'll use it to make sure it's passing to the 
    # repository correctly
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials='testing_abc123')

@pytest.fixture(scope="module") 
def good_api_key():
    now = datetime.now()
    return APIKey(
        id=1,
        hashed_key="xyzabc",
        key_prefix="testing",
        scopes=[],
        manager_id=uuid.uuid4(),
        is_active=True,
        created_at=now,
    )


@pytest.fixture(scope="module") 
def inactive_api_key():
    now = datetime.now()
    return APIKeyOut(
        id=1,
        hashed_key="xyzabc",
        key_prefix="testing",
        manager_id=uuid.uuid4(),
        is_active=False,
        created_at=now,
    )

@pytest.fixture(scope="module") 
def expired_api_key():
    now = datetime.now()
    a_few_minutes_ago = now - timedelta(minutes=2)

    return APIKeyOut(
        id=1,
        hashed_key="xyzabc",
        key_prefix="testing",
        expires_at=a_few_minutes_ago,
        manager_id=uuid.uuid4(),
        is_active=True,
        created_at=now,
    )


@pytest.fixture(scope="module") 
def non_expired_api_key():
    now = datetime.now()
    a_few_minutes_ago = now + timedelta(minutes=2)

    return APIKeyOut(
        id=1,
        hashed_key="xyzabc",
        key_prefix="testing",
        expires_at=a_few_minutes_ago,
        manager_id=uuid.uuid4(),
        is_active=True,
        created_at=now,
    )


async def test_passes_api_key_to_repo(mocker, good_api_key, api_key):
    '''Get token should pass api key to repo to validate'''
    mock_session = AsyncMock()
    mock_api_key_repo = AsyncMock() 
    
    mock_api_key_repo.get_by_api_key_value = AsyncMock(return_value=good_api_key)
    request_mock = AsyncMock()
    mock_api_key_repository_class = mocker.patch(
        API_KEY_REPOSITORY_PATH, 
        return_value=mock_api_key_repo 
    )

    await valid_api_key(request_mock, credentials=api_key, session=mock_session)

    mock_api_key_repository_class.assert_called_once_with(mock_session)
    mock_api_key_repo.get_by_api_key_value.assert_awaited_once_with(api_key.credentials)


async def test_get_api_key_valid_key(mocker, good_api_key, api_key):
    """
    When the repo returns a valid token, it should return the token object.
    """
    mock_session = AsyncMock()
    mock_api_key_repo = AsyncMock() 
    request_mock = AsyncMock()

    mock_api_key_repo.get_by_api_key_value = AsyncMock(return_value=good_api_key)

    mocker.patch(
        API_KEY_REPOSITORY_PATH, 
        return_value=mock_api_key_repo 
    )

    returned_key = await valid_api_key(request_mock, credentials=api_key, session=mock_session)

    assert returned_key == APIKeyOut.model_validate(good_api_key)
    assert returned_key.is_active is True


async def test_get_token_inactive_key(mocker, inactive_api_key, api_key):
    """
    When the returned token is inactive, it should raise a 401.
    """
    mock_session = AsyncMock()
    mock_api_key_repo = AsyncMock() 
    request_mock = AsyncMock()

    mock_api_key_repo.get_by_api_key_value = AsyncMock(return_value=inactive_api_key)

    mocker.patch(
        API_KEY_REPOSITORY_PATH, 
        return_value=mock_api_key_repo 
    )

    with pytest.raises(HTTPException) as exc_info:
        await valid_api_key(request_mock, credentials=api_key, session=mock_session)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Missing or invalid API key" in exc_info.value.detail


async def test_get_token_expired_token(mocker, expired_api_key, api_key):
    """
    When the returned token is expired, it should raise a 401.
    """
    mock_session = AsyncMock()
    mock_api_key_repo = AsyncMock() 
    request_mock = AsyncMock()

    mock_api_key_repo.get_by_api_key_value = AsyncMock(return_value=expired_api_key)

    mocker.patch(
        API_KEY_REPOSITORY_PATH, 
        return_value=mock_api_key_repo 
    )

    with pytest.raises(HTTPException) as exc_info:
        await valid_api_key(request_mock, credentials=api_key, session=mock_session)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "API key is expired" in exc_info.value.detail

async def test_get_token_non_expired_token(mocker, non_expired_api_key, api_key):
    """
    When the returned token is not expired is should not raise and return token.
    """
    mock_session = AsyncMock()
    mock_api_key_repo = AsyncMock() 
    request_mock = AsyncMock()

    mock_api_key_repo.get_by_api_key_value = AsyncMock(return_value=non_expired_api_key)

    mocker.patch(
        API_KEY_REPOSITORY_PATH, 
        return_value=mock_api_key_repo 
    )

    returned_api_key = await valid_api_key(request_mock, credentials=api_key, session=mock_session)

    assert returned_api_key == non_expired_api_key
    assert returned_api_key.is_active is True


