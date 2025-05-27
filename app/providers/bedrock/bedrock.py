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
        name="Llama 3.2 11B", # Note: The setup script refers to llama3-8b-instruct-v1:0. Ensure consistency or use appropriate model ID.
        id="llama3211b", # This ID should match the key in .env, e.g., BEDROCK_MODELS__LLAMA3211B__ARN
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
        use_mock_providers: bool = Field(default=False, alias="USE_MOCK_PROVIDERS") # Load from .env

        @model_validator(mode="after")
        def ensure_arns_present(self):
            # Only validate ARNs if not using mock providers
            if not self.use_mock_providers:
                missing = [
                    key
                    for key, model in self.bedrock_models.__dict__.items()
                    if isinstance(model, BedrockModel) and not model.arn
                ]
                if missing:
                    raise ValueError(
                        "Missing ARN for Bedrock models (live mode): " + ", ".join(missing)
                    )
            return self


    
    def __init__(self):
        self.settings = self.Settings()
        # Check if we should be using mocks based on the global setting,
        # rather than a Bedrock-specific one, if USE_MOCK_PROVIDERS is meant to be global.
        # However, the current setup script puts USE_MOCK_PROVIDERS in .env,
        # so BedRockBackend.Settings will pick it up.

        # If self.settings.use_mock_providers is True, this backend might not even be used
        # if the main settings.py logic for backend_map handles mocks.
        # For now, this internal setting makes the ARN validation conditional.

        self.retry_config = AioConfig(
            retries={"max_attempts": 5, "mode": "standard",},
            region_name=self.settings.aws_default_region
        )


    @property
    def models(self):
        return [LLMModel(**v) for v in self.settings.bedrock_models.model_dump().values()]


    async def invoke_model(self, payload: ChatRequest) -> ChatRepsonse:
        # This check should ideally happen before calling specific provider logic
        # For example, in app.config.settings.get_settings() when building _backend_map
        # If mock providers are used, the actual BedRockBackend might not be invoked.
        # However, if it is invoked, this ensures it doesn't proceed without ARNs in live mode.
        if not self.settings.use_mock_providers and not all(model.arn for model_key, model in self.settings.bedrock_models.__dict__.items() if isinstance(model, BedrockModel)):
             raise ValueError("Bedrock ARNs are required for live mode but are missing.")

        converted = core_to_bedrock(payload)
        session = aioboto3.Session()
        async with session.client("bedrock-runtime", config=self.retry_config) as client:
            body = converted.model_dump(exclude_none=True, by_alias=True)
            
            # Get the specific model instance from bedrock_models settings
            model_setting = getattr(self.settings.bedrock_models, converted.model_id, None)
            if not model_setting or not model_setting.arn:
                # This case should be caught by ensure_arns_present if not using mocks
                # Or, if using mocks, this backend shouldn't be called.
                # If it's called with mocks and an ARN is needed here, it's an issue.
                # For now, assume ARNs are populated if not in mock mode.
                raise ValueError(f"ARN for model {converted.model_id} not found in Bedrock settings.")
            
            arn = model_setting.arn
            
            body['modelId'] = arn
            try:
                response = await client.converse(**body)
            except botocore.exceptions.ClientError as e:
                # Log the specific error details from Bedrock
                log.error("Bedrock ClientError", error=str(e), model_id=converted.model_id, request_body=body)
                raise InvalidInput(f"Bedrock API error for model {converted.model_id}: {str(e)}", original_exception=e)
            
            log.info("model metrics", model=converted.model_id, **response['metrics'])
        
            res = ConverseResponse(**response)
            return bedrock_chat_response_to_core(res, model=converted.model_id)


    async def embeddings(self, payload: EmbeddingRequest) -> EmbeddingResponse: 
        if not self.settings.use_mock_providers and not all(model.arn for model_key, model in self.settings.bedrock_models.__dict__.items() if isinstance(model, BedrockModel)):
             raise ValueError("Bedrock ARNs are required for live mode but are missing.")

        converted = core_embed_request_to_bedrock(payload)
        body = converted.model_dump_json(exclude_none=True)
        
        model_setting = getattr(self.settings.bedrock_models, payload.model, None)
        if not model_setting or not model_setting.arn:
            raise ValueError(f"ARN for embedding model {payload.model} not found in Bedrock settings.")
        
        modelId = model_setting.arn

        session = aioboto3.Session()        
        async with session.client("bedrock-runtime", config=self.retry_config) as client:
            try:
                response = await client.invoke_model(
                    body=body,
                    modelId=modelId,
                    accept = '*/*',
                    contentType = 'application/json'
                    )
            except botocore.exceptions.ClientError as e:
                log.error("Bedrock ClientError for embeddings", error=str(e), model_id=payload.model, request_body=body)
                raise InvalidInput(f"Bedrock API error for embedding model {payload.model}: {str(e)}", original_exception=e)


            headers = response['ResponseMetadata']['HTTPHeaders']

            latency = headers.get('x-amzn-bedrock-invocation-latency', 'N/A') # Use .get for safety
            token_count_str = headers.get('x-amzn-bedrock-input-token-count', '0') # Use .get and default
            token_count = int(token_count_str) if token_count_str.isdigit() else 0

            log.info("embedding", latency=latency, model=modelId, input_token_count=token_count)
            #resp_body_bytes = await response.get("body").read()
            # resp = CohereRepsonse.model_validate_json(resp_body_bytes)
          
            log.info("model metrics", latency=latency, model=modelId)
            resp = await response.get("body").read()
            

            return bedorock_embed_reposonse_to_core(model=modelId, resp=resp, token_count=token_count)

