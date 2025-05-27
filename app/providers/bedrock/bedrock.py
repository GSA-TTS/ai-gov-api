'''
Provider.bedrock
~~~~~~~~~~~~~~~~

This module is responsible for accepting requests in the form of the Core API Model, 
interacting with various bedrock models, and returning an well-formed response.

It has three part:

1. Getting its settings. This uses Pydantic's `env_nested_delimiter`, which allows defining nested
   variables such as: BEDROCK_MODELS__CLAUDE_3_5_SONNET__ARN to set the right nested setting
2. Converting to and from the core schema format
3. Implementing a subclass of BackendBase

'''


import structlog
from typing import  Literal

import aioboto3
from aiobotocore.config import AioConfig
import botocore.exceptions

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.providers.exceptions import InvalidInput
from app.providers.base import Backend, LLMModel
from .adapter_from_core import core_to_bedrock, core_embed_request_to_bedrock
from .adapter_to_core import bedrock_chat_response_to_core, bedorock_embed_reposonse_to_core
from ..core.chat_schema import ChatRequest, ChatRepsonse
from ..core.embed_schema import EmbeddingResponse, EmbeddingRequest
from .converse_schemas import ConverseResponse
from .cohere_embedding_schemas import CohereRepsonse


log = structlog.get_logger()

# Settings
# This is mostly about getting secrets
# but also makes it easy to define supported 
# in on location

class BedrockModel(LLMModel):  
    name: str
    id: str
    arn: str
    capability: Literal['chat', 'embedding']
 

class BedrockModelsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        nested_model_default_partial_update=True,
        extra='ignore',
        env_nested_delimiter="__"
    )

    claude_3_5_sonnet: BedrockModel = BedrockModel(
        name="Claude 3.5 Sonnet",
        id="claude_3_5_sonnet",
        capability="chat",
        arn="",                         
    )
    claude_3_7_sonnet: BedrockModel = BedrockModel(
        name="Claude 3.7 Sonnet",
        id="claude_3_7_sonnet",
        capability="chat",
        arn="",                         
    )
    claude_3_haiku: BedrockModel = BedrockModel(
        name="Claude 3 Haiku",
        id="claude_3_haiku",
        capability="chat",
        arn="",                         
    )
    llama3211b: BedrockModel = BedrockModel(
        name="Llama 3.2 11B",
        id="llama3211b",
        capability="chat",
        arn="",                         
    )
    cohere_english_v3: BedrockModel = BedrockModel(
        name="Cohere English Ebmeddings",
        id="cohere_english_v3",
        capability="embedding",
        arn="",                         
    )


# Handle requests to Bedrock
# `models` is a required property and will be used to register models
# to ensure the correct instance handles requests. This is how the 
# application knows which backends serve which models.

class BedRockBackend(Backend):
    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_file='.env',extra='ignore', env_file_encoding='utf-8', env_nested_delimiter="__" )
        aws_default_region: str = Field(default=...)
        bedrock_models: BedrockModelsSettings = BedrockModelsSettings()
        
        @model_validator(mode="after")
        def ensure_arns_present(self):
            missing = [
                key
                for key, model in self.bedrock_models.__dict__.items()
                if isinstance(model, BedrockModel) and not model.arn
            ]
            if missing:
                raise ValueError(
                    "Missing ARN for: " + ", ".join(missing)
                )
            return self


    
    def __init__(self):
        self.settings = self.Settings()
        self.retry_config = AioConfig(
            retries={"max_attempts": 5, "mode": "standard",},
            region_name=self.settings.aws_default_region
        )


    @property
    def models(self):
        return [LLMModel(**v) for v in self.settings.bedrock_models.model_dump().values()]


    async def invoke_model(self, payload: ChatRequest) -> ChatRepsonse:
        converted = core_to_bedrock(payload)
        session = aioboto3.Session()
        async with session.client("bedrock-runtime", config=self.retry_config) as client:
            body = converted.model_dump(exclude_none=True, by_alias=True)
            arn = getattr(self.settings.bedrock_models, converted.model_id).arn
            
            body['modelId'] = arn
            try:
                response = await client.converse(**body)
            except botocore.exceptions.ClientError as e:
                raise InvalidInput(str(e), original_exception=e)
            
            log.info("model metrics", model=converted.model_id, **response['metrics'])
        
            res = ConverseResponse(**response)
            return bedrock_chat_response_to_core(res, model=converted.model_id)


    async def embeddings(self, payload: EmbeddingRequest) -> EmbeddingResponse: 
        converted = core_embed_request_to_bedrock(payload)
        body = converted.model_dump_json(exclude_none=True)
        modelId = getattr(self.settings.bedrock_models, payload.model).arn 

        session = aioboto3.Session()        
        async with session.client("bedrock-runtime", config=self.retry_config) as client:
            

            response = await client.invoke_model(
                body=body,
                modelId=modelId,
                accept = '*/*',
                contentType = 'application/json'
                )

            headers = response['ResponseMetadata']['HTTPHeaders']
            latency = headers['x-amzn-bedrock-invocation-latency']
            token_count = headers['x-amzn-bedrock-input-token-count']
            log.info("model metrics", latency=latency, model=modelId)
            resp = await response.get("body").read()

            resp = CohereRepsonse.model_validate_json(resp)

            return bedorock_embed_reposonse_to_core(model=modelId, resp=resp, token_count=token_count)
