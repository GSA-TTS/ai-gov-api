from datetime import datetime
import uuid
import pytest

from fastapi import HTTPException, status
from app.auth.schemas import APIKeyOut, Scope
from app.auth.dependencies import RequiresScope



@pytest.mark.parametrize("key_scopes, required_scopes, is_valid", [
    ([], [], True),
    ([Scope.USERS_READ, Scope.USERS_WRITE], [], True),
    ([Scope.USERS_READ, Scope.USERS_WRITE], [Scope.USERS_WRITE], True),
    ([Scope.USERS_WRITE], [Scope.USERS_WRITE], True),
    ([Scope.USERS_READ],[Scope.USERS_WRITE], False),
    ([], [Scope.USERS_WRITE], False),
    ([Scope.USERS_READ, Scope.USERS_WRITE], [Scope.USERS_WRITE, Scope.ADMIN], False),
    ([Scope.USERS_READ, Scope.USERS_WRITE], [Scope.USERS_READ, Scope.USERS_WRITE, Scope.ADMIN], False),
])
def test_required_scopes(key_scopes, required_scopes, is_valid):
    '''
    Every scope in required scopes must be present in the key's scopes
    '''
    now = datetime.now()

    api_key = APIKeyOut(
        id=1,
        hashed_key="abc123",
        key_prefix="testing",
        manager_id=uuid.uuid4(),
        scopes=key_scopes,
        is_active=True,
        created_at=now,
    )

    scope = RequiresScope(required_scopes)
    
    if is_valid:
        returned_key = scope(api_key)
        assert returned_key == api_key
    else:
        with pytest.raises(HTTPException) as exc_info:
            returned_key = scope(api_key)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Not Authorized" in exc_info.value.detail
