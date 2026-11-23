from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict, EmailStr

class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str = Field(min_length=1, max_length=50)
    email: EmailStr = Field(max_length=120)

class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserResponse(UserBase):

    id: int
    image_file: str | None
    image_path: str


class PostBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    title: str = Field(min_length= 1, max_length= 100)
    content: str = Field(min_length = 1)

class PostCreate(PostBase):
    user_id: int

class PostResponse(PostBase):
    id: int
    user_id: int
    date_posted: datetime
    author: UserResponse