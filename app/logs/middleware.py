import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import structlog
from structlog.contextvars import clear_contextvars, bind_contextvars
from app.logs.logging_context import request_id_ctx


class StructlogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        clear_contextvars()
        request_id_ctx.set(str(uuid.uuid4()))
        start_time = time.time()
        
        bind_contextvars(
            request_id=request_id_ctx.get(),
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", ""),
        )

        request_logger = structlog.get_logger()
        request_logger.info("Request started")
        
        try:
            response = await call_next(request)
        except Exception:   # Only uncaught errors, this should not catch http exceptions like 404s
            duration_ms = round((time.time() - start_time) * 1000, 2)
            request_logger.exception("Request failed", duration_ms=duration_ms)
            raise 
        else:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            request_logger = request_logger.bind(
                key_id=getattr(request.state, "api_key_id", None)
            )
            request_logger.info(
                "Request completed",
                status_code=response.status_code,
                duration_ms=duration_ms
            )
            
            return response
            
