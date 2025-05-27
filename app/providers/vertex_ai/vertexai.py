import time
from typing import Literal, List
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import structlog
import os # Added for checking environment variables

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
    gemini_2_0_flash_light:VertexModel = VertexModel( # Corrected model ID based on common Vertex naming
        name="Gemini 2.0 Flash Light",
        id="gemini-2.0-flash-lite", # Common ID, adjust if different in your setup
        capability="chat"
    )
    gemini_2_5_pro:VertexModel = VertexModel(
        name="Gemini 2.5 Pro",
        id="gemini-2.5-pro-preview-05-06", # Ensure this ID is accurate
        capability="chat"
    )
    text_embedding_005:VertexModel = VertexModel(
        name="Text embedding 005",
        id="text-embedding-005", # Common ID, adjust if different
        capability="embedding"
    )


class VertexBackend(Backend):
    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_file='.env',extra='ignore', env_file_encoding='utf-8', env_nested_delimiter="__" )
        vertex_project_id:str = Field(default="") # Make it optional by default, validator will check
        google_application_credentials: str = Field(default="") # Make it optional, validator will check
        vertex_models:VertexModelsSettings = VertexModelsSettings()
        use_mock_providers: bool = Field(default=False, alias="USE_MOCK_PROVIDERS")

        @model_validator(mode="after")
        def ensure_credentials_present_if_not_mocking(self):
            if not self.use_mock_providers:
                if not self.vertex_project_id:
                    raise ValueError("VERTEX_PROJECT_ID is required for Vertex AI when not using mock providers.")
                if not self.google_application_credentials:
                    raise ValueError("GOOGLE_APPLICATION_CREDENTIALS path is required for Vertex AI when not using mock providers.")
                # You might also want to check if the file at google_application_credentials actually exists
                # if not os.path.exists(self.google_application_credentials):
                #     raise ValueError(f"GOOGLE_APPLICATION_CREDENTIALS file not found at: {self.google_application_credentials}")
            return self

    def __init__(self):
        self.settings = self.Settings()
        
        # Only initialize Vertex AI SDK if not using mocks and credentials are provided
        if not self.settings.use_mock_providers:
            if not self.settings.vertex_project_id:
                log.warn("Vertex AI: Not initializing SDK because VERTEX_PROJECT_ID is missing (live mode).")
                return
            if not self.settings.google_application_credentials:
                log.warn("Vertex AI: Not initializing SDK because GOOGLE_APPLICATION_CREDENTIALS is missing (live mode).")
                return
            if not os.path.exists(self.settings.google_application_credentials):
                log.warn(f"Vertex AI: Not initializing SDK because GOOGLE_APPLICATION_CREDENTIALS file not found at: {self.settings.google_application_credentials} (live mode).")
                return

            # Set the environment variable for the SDK
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.settings.google_application_credentials
            try:
                vertexai.init(project=self.settings.vertex_project_id, location="us-central1")
                log.info("Vertex AI SDK initialized", project_id=self.settings.vertex_project_id)
            except Exception as e:
                log.error("Vertex AI SDK initialization failed", error=str(e), project_id=self.settings.vertex_project_id)
                # Depending on strictness, you might want to raise an error here
                # For now, just log, as the main settings load might continue for mocks
        else:
            log.info("Vertex AI: Mock providers enabled, skipping Vertex AI SDK initialization.")


    @property
    def models(self):
        return [LLMModel(**v) for v in self.settings.vertex_models.model_dump().values()]


    async def invoke_model(self, payload: ChatRequest) -> ChatRepsonse:
        if self.settings.use_mock_providers:
            # This should be handled by the mock provider if USE_MOCK_PROVIDERS is global
            # For safety, if this backend is somehow called directly in mock mode:
            raise NotImplementedError("VertexBackend should not be called directly when mock providers are enabled.")
        if not self.settings.vertex_project_id or not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            raise ValueError("Vertex AI project ID or credentials not configured for live mode.")

        model_id = payload.model
        try:
            model = GenerativeModel(model_id)
        except Exception as e:
            log.error("Vertex AI: Failed to instantiate GenerativeModel", model_id=model_id, error=str(e))
            raise InvalidInput(f"Failed to instantiate Vertex AI model {model_id}: {str(e)}", original_exception=e)

        vertex_req = convert_chat_request(payload)
        try:
            start_time = time.perf_counter_ns()
            response = await model.generate_content_async(**dict(vertex_req))
            end_time = time.perf_counter_ns()
            latency_ms = round((end_time - start_time) / 1_000_000)
            log.info("model metrics", model=model_id, latencyMS=latency_ms)
        except core_exceptions.InvalidArgument as e:
            log.error("Vertex AI InvalidArgument", error=str(e), model_id=model_id, request_details=vertex_req.model_dump_json(indent=2))
            raise InvalidInput(f"Vertex AI API error (InvalidArgument) for model {model_id}: {str(e)}", original_exception=e)
        except Exception as e: # Catch other potential Vertex AI errors
            log.error("Vertex AI general error during generate_content_async", error=str(e), model_id=model_id)
            raise InvalidInput(f"Vertex AI API general error for model {model_id}: {str(e)}", original_exception=e)
        


        return convert_chat_vertex_response(response, model=model_id)
  
    async def embeddings(self, payload: EmbeddingRequest): 
        if self.settings.use_mock_providers:
            raise NotImplementedError("VertexBackend embeddings should not be called directly when mock providers are enabled.")
        if not self.settings.vertex_project_id or not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            raise ValueError("Vertex AI project ID or credentials not configured for live mode.")

        try:
            model = TextEmbeddingModel.from_pretrained(payload.model)
        except Exception as e:
            log.error("Vertex AI: Failed to instantiate TextEmbeddingModel", model_id=payload.model, error=str(e))
            raise InvalidInput(f"Failed to instantiate Vertex AI embedding model {payload.model}: {str(e)}", original_exception=e)

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
            log.error("Vertex AI InvalidArgument for embeddings", error=str(e), model_id=payload.model, request_details=req.model_dump_json(indent=2))
            raise InvalidInput(f"Vertex AI API error (InvalidArgument) for embedding model {payload.model}: {str(e)}", original_exception=e)
        except Exception as e: # Catch other potential Vertex AI errors
            log.error("Vertex AI general error during get_embeddings_async", error=str(e), model_id=payload.model)
            raise InvalidInput(f"Vertex AI API general error for embedding model {payload.model}: {str(e)}", original_exception=e)

        return vertex_embed_reposonse_to_core(response, model=payload.model)

