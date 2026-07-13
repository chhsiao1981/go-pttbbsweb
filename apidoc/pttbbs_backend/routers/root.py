from typing import Annotated
from fastapi import APIRouter, Query

from .const import API_PREFIX
from ..models.index import Index, IndexParams

router = APIRouter(prefix=API_PREFIX)


@router.get("/")
async def index(query: Annotated[IndexParams, Query()]) -> Index:
    return Index(Data=query)
