from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, UUID4 


# These are mostly a placeholders to get a permission model working
# It's not clear that this should not be it's own DB table but for now this is is simpler

class Scope(str, Enum):
    # User management
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    
    # Inference
    MODELS_INFERENCE = "models:inference"
    MODELS_EMBEDDING = "models:embedding"
        
    # System-level permissions
    ADMIN = "admin"

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"



class APIKeyBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    manager_id: UUID4
    scopes: list[Scope] = []
    key_prefix: str
    is_active: bool = True
    expires_at: datetime | None = None
    last_used_at: datetime | None = None

class APIKeyCreate(APIKeyBase):
    pass
class APIKeyNew(APIKeyBase):
    hashed_key: str

class APIKeyOut(APIKeyBase):
    id: int 
    hashed_key: str
    created_at: datetime

class APIKeyOutOnce(APIKeyOut):
    token:str