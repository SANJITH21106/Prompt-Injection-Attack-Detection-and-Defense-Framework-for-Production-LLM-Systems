"""
Chat API Router — POST /api/chat
Accepts user prompt, runs the full security pipeline, returns response.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.pipeline import RequestPipeline

router = APIRouter(prefix="/api", tags=["chat"])

_pipeline = RequestPipeline()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    """
    Process a chat request through the full security pipeline.
    Returns the response along with complete security analysis metadata.
    """
    return await _pipeline.process(request.prompt, db)
