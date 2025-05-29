from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.users.models import User
from app.users.schemas import UserCreate, UserUpdate
from app.common.exceptions import ResourceNotFoundError, DuplicateResourceError

class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        
    async def create(self,user:UserCreate) -> User:
        new_user = User(**user.model_dump())
        existing_user = await self.get_by_email(new_user.email)
        if existing_user is not None:
            raise DuplicateResourceError(resource_name="User", identifier=new_user.email)
        
        self.session.add(new_user)
        await self.session.flush([new_user])
        return new_user        

    async def get(self, user_id: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.id==user_id)
        )
        result = result.scalars().one_or_none()
        if result is None:
            raise ResourceNotFoundError(resource_name='User', identifier=user_id)
        return result
    
    async def get_by_email(self, email: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.email==email)
        )
        result = result.scalars().one_or_none()
        if result is None:
            raise ResourceNotFoundError(resource_name='User', identifier=email)
        return result

    async def update(self, email:str, user:UserUpdate) -> User:
        to_update = await self.get_by_email(email)
        if to_update is None:
            raise ResourceNotFoundError(resource_name='User', identifier=email)

        values = user.model_dump(exclude_unset=True)
        for k, v in values.items():
            setattr(to_update, k, v)

        return to_update