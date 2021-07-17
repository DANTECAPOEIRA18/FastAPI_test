from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    identification: int
    password: str
    username: str
    is_superuser: bool

    class Config:
        orm_mode = True


class UserDelete(BaseModel):
    identification: int


class UserInDB(User):
    hashed_password: str


class UserCreate(BaseModel):
    identification: int
    password: str
    username: str
    is_superuser: bool


class UserUpdate(BaseModel):
    password: str
    username: str
    is_superuser: bool
