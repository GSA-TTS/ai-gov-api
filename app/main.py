import asyncio
from contextlib import asynccontextmanager
from fastapi import  FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.logs.logging_config import setup_structlog
from app.logs.middleware import StructlogMiddleware
from app.logs.logging_context import request_id_ctx
from app.routers import api_v1, root, users, tokens
from app.common.exceptions import ResourceNotFoundError, DuplicateResourceError
from app.db.session import engine
from app.services.billing import billing_worker, drain_billing_queue
from sqlalchemy.exc import IntegrityError

# this is only here until we actually use the users model
# somewhere other than a relationship. SqlAlchemy has trouble
# building forward references when the model has not actuall be imported into the code
from app.users.models import User # noqa 401 

# Disabled becuase we capture this infor with middleware
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn").disabled = True
logging.getLogger("uvicorn.error").disabled = True



@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_structlog()
    asyncio.create_task(billing_worker())
    
    yield

    await engine.dispose()
    await drain_billing_queue()


origins = [
    "http://localhost",
    "http://localhost:8080",
    "*"
]
app = FastAPI(lifespan=lifespan)

app.add_middleware(StructlogMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(ResourceNotFoundError)
async def resource_not_found_exception_handler(request: Request, exc: ResourceNotFoundError):
    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )

@app.exception_handler(DuplicateResourceError)
async def duplicate_resource_exception_handler(request: Request, exc: ResourceNotFoundError):
    return JSONResponse(
        status_code=409,
        content={"detail": str(exc)},
    )

@app.exception_handler(IntegrityError)
async def db_integrity_exception_handler(request: Request, exc: IntegrityError):
    '''
    This is a little hacky. SqlAlchemy's integrity error covers many cases
    Null contrainst, unique contraints, etc and delviers a detailed message
    we probably don't want to return to the user. TODO: revist.
    '''
    message_lines = exc._message().split('\n')
    return JSONResponse(
        status_code=400, 
        content={"detail": message_lines[0]},
    )

@app.exception_handler(Exception)
async def json_500_handler(request: Request, exc: Exception):
    """
    Starlette catches all errors and creates a response, but it's
    the plain text 'Internal Server Error' which is a little 
    unfriendly to callers expecting json. This makes it a bit
    better.
    """

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal Server Error",
            "request_id": request_id_ctx.get(),
        }
    )

app.include_router(
    root.router,
    include_in_schema=False,
    prefix=""
)

app.include_router(
    api_v1.router,
    prefix="/api/v1"
)

app.include_router(
    users.router,
    prefix="/users",
    include_in_schema=False
)

app.include_router(
    tokens.router,
    prefix="/tokens",
    include_in_schema=False
)