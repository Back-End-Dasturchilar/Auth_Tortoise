from pydantic import BaseModel
from datetime import datetime


class UserGet(BaseModel):
    id: int
    username: str
    created_at: datetime


class Login(BaseModel):
    username: str
    password: str


class Register(BaseModel):
    username: str
    password: str
    password2: str


class ChangePassword(BaseModel):
    password2: str
    password: str


class CategoryGet(BaseModel):
    id: int
    name: str
    created_at: datetime


class CategoryPost(BaseModel):
    name: str


class CategoryUpdate(BaseModel):
    name: str = None


class BlogGet(BaseModel):
    id: int
    title: str
    content: float
    created_at: datetime


class BlogPost(BaseModel):
    title: str
    content: float
    category: int


class BlogUpdate(BaseModel):
    title: str = None
    content: float = None
    category: int = None
