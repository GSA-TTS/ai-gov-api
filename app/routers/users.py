from fastapi import APIRouter, Depends
from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.users.schemas import UserCreate, UserOut, UserUpdate
from app.users.repositories import UserRepository
from app.auth.dependencies import RequiresScope
from app.auth.schemas import Scope
from app.db.session import get_db_session



router = APIRouter()

@router.post("/create")
async def create_user(
    user: UserCreate, 
    api_key=Depends(RequiresScope([Scope.ADMIN])),
    session: AsyncSession = Depends(get_db_session)
) -> UserOut:
    user_repo = UserRepository(session)
    new_user = await user_repo.create(user)
    await session.commit()
    await session.refresh(new_user) 
    return UserOut.model_validate(new_user)

@router.get("/{email}")
async def get_by_email(
    email:EmailStr,
    api_key=Depends(RequiresScope([Scope.ADMIN])),
    session: AsyncSession = Depends(get_db_session),
) -> UserOut:
    user_repo = UserRepository(session)
    user_orm = await user_repo.get_by_email(email=email)
    return UserOut.model_validate(user_orm)
     

@router.post("/update/{email}")
async def update(
    update: UserUpdate,
    email:EmailStr,
    api_key=Depends(RequiresScope([Scope.ADMIN])),
    session: AsyncSession = Depends(get_db_session),
) -> UserOut:
    user_repo = UserRepository(session)
    updated_user_orm = await user_repo.update(email=email, user=update)
    await session.commit()
    await session.refresh(updated_user_orm) 
    return UserOut.model_validate(updated_user_orm)
        
