from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.config.settings import get_settings
from app.db.models import Base

settings = get_settings()

database_url = settings.postgres_connection
engine = create_async_engine(database_url, echo=settings.database_echo)

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

        
async_session = async_sessionmaker(
    bind=engine, class_=AsyncSession, autocommit=False, autoflush=True
)

# Dependency for FastAPI injection that handles session lifecyle
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    
    async with async_session(expire_on_commit=False) as session:
        try:
            yield session
        except:
            await session.rollback()
            raise
        finally:
            await session.close()
