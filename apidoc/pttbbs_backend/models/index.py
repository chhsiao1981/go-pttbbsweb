from pydantic import BaseModel, Field


class IndexParams(BaseModel):
    In: int = Field(alias="in")


class Index(BaseModel):
    Data: IndexParams = Field(alias="data")
