from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.schemas import APIKeyCreate, APIKeyOut, APIKeyNew, APIKeyOutOnce
from app.auth.repositories import APIKeyRepository, APIKey
from app.auth.dependencies import RequiresScope
from app.auth.utils import generate_api_key
from app.auth.schemas import Scope
from app.db.session import get_db_session



router = APIRouter()

@router.post("/create")
async def create_api_key(
    apikey: APIKeyCreate, 
    _: Annotated[APIKey, Depends(RequiresScope([Scope.ADMIN]))],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> APIKeyOutOnce:
    repo = APIKeyRepository(session)
    token, hashed = generate_api_key(apikey.key_prefix, 16)
    new_key = await repo.create(APIKeyNew(hashed_key=hashed, **apikey.model_dump()))
   
    await session.commit()
    await session.refresh(new_key) 

    db_model = APIKeyOut.model_validate(new_key)

    return APIKeyOutOnce(token=token, **db_model.model_dump())
        
@router.post("/is_active/{id}")
async def converse(
    id:int,
    is_active:bool,
    api_key=Depends(RequiresScope([Scope.ADMIN])),
    session: AsyncSession = Depends(get_db_session),
) -> APIKeyOut:
    api_key_repo = APIKeyRepository(session)
    updated_api_key_orm = await api_key_repo.set_is_active(id, is_active)
    
    await session.commit()
    await session.refresh(updated_api_key_orm) 
    return APIKeyOut.model_validate(updated_api_key_orm)
        
