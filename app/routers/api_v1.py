from typing import List
from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import RequiresScope, valid_api_key
from app.auth.schemas import Scope
from app.providers.base import LLMModel
from app.providers.dependencies import Backend
from app.providers.exceptions import InvalidInput
from app.config.settings import get_settings
from app.providers.open_ai.schemas import ChatCompletionRequest, ChatCompletionResponse, EmbeddingRequest, EmbeddingResponse
from app.providers.open_ai.adapter_to_core import openai_chat_request_to_core, openai_embed_request_to_core
from app.providers.open_ai.adapter_from_core import core_chat_response_to_openai, core_embed_response_to_openai

router = APIRouter()

@router.get("/models")
async def models(
    settings=Depends(get_settings),
    api_key=Depends(valid_api_key)
) -> List[LLMModel]:
    return  [backend for _, backend in settings.backend_map.values()]


@router.post("/chat/completions")
async def converse(
    req: ChatCompletionRequest, 
    api_key=Depends(RequiresScope([Scope.MODELS_INFERENCE])),
    backend=Depends(Backend('chat'))
) -> ChatCompletionResponse:
    try:
        core_req = openai_chat_request_to_core(req)
        resp = await backend.invoke_model(core_req)
        return core_chat_response_to_openai(resp)
    except InvalidInput as e:
        error_detail = {"error": "Bad Request", "message": str(e)}
        if e.field_name:
            error_detail["field"] = e.field_name
        raise HTTPException(status_code=400, detail=error_detail)



@router.post("/embeddings")
async def embeddings(
    req: EmbeddingRequest,
    api_key=Depends(RequiresScope([Scope.MODELS_EMBEDDING])),
    backend=Depends(Backend('embedding'))
) -> EmbeddingResponse:
    core_req = openai_embed_request_to_core(req)
    resp = await backend.embeddings(core_req)
    return core_embed_response_to_openai(resp)
