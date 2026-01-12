from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=14, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class MFALogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=14, max_length=128)
    totp_code: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_verified: bool

    class Config:
        from_attributes = True

