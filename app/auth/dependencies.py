from datetime import datetime
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.db.session import get_db_session
from app.auth.schemas import APIKeyOut, Scope
from app.auth.repositories import APIKeyRepository

logger = structlog.get_logger()

security = HTTPBearer()

async def valid_api_key(
    request: Request,
    credentials:HTTPAuthorizationCredentials =  Depends(security), 
    session: AsyncSession=Depends(get_db_session),
    ) -> APIKeyOut:
    '''
    Auth dependency injection that looks for the API key and returns the user.
    If the API key does not exist, raises 401.
    '''
    request_api_key = credentials.credentials
    api_key = await APIKeyRepository(session).get_by_api_key_value(request_api_key)
    
    if api_key is not None:
        # allow logging of api key id
        request.state.api_key_id = api_key.id

    if api_key is None or not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key"
        )
    if api_key.expires_at is not None:
        now = datetime.now()
        if api_key.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key is expired"
            ) 

    return APIKeyOut.model_validate(api_key)
        

class RequiresScope:
    def __init__(self, scopes: list[Scope]):
        self.scopes = set(scopes)

    def __call__(
        self,
        api_key: APIKeyOut = Depends(valid_api_key)
        ) -> APIKeyOut:
        
        if len(self.scopes) == 0:
            return api_key
        
        if self.scopes.issubset(set(api_key.scopes)):
            return api_key

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authorized"
        ) 
