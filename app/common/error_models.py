from pydantic import BaseModel
from typing import Dict, Any

class ErrorResponse(BaseModel):
    detail: str

# This is only to help fastAPI document error types
# when generating swagger docs.
ERROR_RESPONSES: Dict[int | str, Dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Bad request to Model"},
    403: {"model": ErrorResponse, "description": "Access denied"},
    404: {"model": ErrorResponse, "description": "Model not found"},
    429: {"model": ErrorResponse, "description": "Throttled by Model Provider"},
    503: {"model": ErrorResponse, "description": "Model unavailable"},
}