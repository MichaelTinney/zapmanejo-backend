from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
from uuid import UUID

class TenantCreate(BaseModel):
    name: str
    subdomain: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    tenant_id: UUID

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AnimalCreate(BaseModel):
    name: str
    category: str
    weight: Optional[int] = None
    location: Optional[str] = None
    tenant_id: UUID
