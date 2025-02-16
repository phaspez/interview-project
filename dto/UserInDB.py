from pydantic import BaseModel

class UserInDB(BaseModel):
    full_name: str
    gender: str
    hashed_password: str
    birth_year: int