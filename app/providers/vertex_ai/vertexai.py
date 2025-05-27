import time
from typing import Literal, List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import structlog

import vertexai
from google.api_core import exceptions as core_exceptions
from vertexai.generative_models import GenerativeModel
from vertexai.language_models import TextEmbeddingModel, TextEmbedding
from ..core.embed_schema import EmbeddingRequest

from app.providers.exceptions import InvalidInput
from app.providers.base import Backend, LLMModel
from ..core.chat_schema import ChatRequest, ChatRepsonse
from .adapter_from_core import convert_chat_request, convert_embedding_request
from .adapter_to_core import convert_chat_vertex_response, vertex_embed_reposonse_to_core

log = structlog.get_logger()

class VertexModel(LLMModel):  
    name: str
    id: str
    capability: Literal['chat', 'embedding']
 

class VertexModelsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        nested_model_default_partial_update=True,
        extra='ignore',
        env_nested_delimiter="__"
    )
    gemini_2_0_flash:VertexModel = VertexModel(
        name="Gemini 2.0 Flash",
        id="gemini-2.0-flash",
        capability="chat"
    )
    gemini_2_0_flash_light:VertexModel = VertexModel(
        name="Gemini 2.0 Flash Light",
        id="gemini-2.0-flash-lite",
        capability="chat"
    )
    gemini_2_5_pro:VertexModel = VertexModel(
        name="Gemini 2.5 Pro",
        id="gemini-2.5-pro-preview-05-06",
        capability="chat"
    )
    text_embedding_005:VertexModel = VertexModel(
        name="Text embedding 005",
        id="text-embedding-005",
        capability="embedding"
    )


class VertexBackend(Backend):
    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_file='.env',extra='ignore', env_file_encoding='utf-8', env_nested_delimiter="__" )
        vertex_project_id:str = Field(default=...)
        vertex_models:VertexModelsSettings = VertexModelsSettings()

    def __init__(self):
        self.settings = self.Settings()
        vertexai.init(project=self.settings.vertex_project_id, location="us-central1")

    @property
    def models(self):
        return [LLMModel(**v) for v in self.settings.vertex_models.model_dump().values()]


    async def invoke_model(self, payload: ChatRequest) -> ChatRepsonse:
        model_id = payload.model
        model = GenerativeModel(model_id)
    
        vertex_req = convert_chat_request(payload)
        try:
            start_time = time.perf_counter_ns()
            response = await model.generate_content_async(**dict(vertex_req))
            end_time = time.perf_counter_ns()
            latency_ms = round((end_time - start_time) / 1_000_000)
            log.info("model metrics", model=model_id, latencyMS=latency_ms)
        except core_exceptions.InvalidArgument as e:
            raise InvalidInput(str(e), original_exception=e)
        


        return convert_chat_vertex_response(response, model=model_id)
  
    # https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/text-embeddings-api
    async def embeddings(self, payload: EmbeddingRequest): 
        model = TextEmbeddingModel.from_pretrained(payload.model)
        req = convert_embedding_request(payload)
        # vertex is fussy with types: model_dump() converts the TextEmbeddingInput to dicts
        # which are rejeted by the api. dict() is a shallow copy of the outer obejct
        try:
            start_time = time.perf_counter_ns()
            response: List[TextEmbedding] = await model.get_embeddings_async(**dict(req))
            end_time = time.perf_counter_ns()
            latency_ms = round((end_time - start_time) / 1_000_000)
            log.info("model metrics", model=payload.model, latencyMS=latency_ms)

        except core_exceptions.InvalidArgument as e:
            raise InvalidInput(str(e), original_exception=e)


        return vertex_embed_reposonse_to_core(response, model=payload.model)