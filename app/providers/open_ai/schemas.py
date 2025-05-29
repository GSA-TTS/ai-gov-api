from pydantic import (
    Base64Bytes,
    BaseModel,
    ConfigDict,
    confloat,
    Field,
    field_serializer,
    NonNegativeInt,
    PositiveInt,
    StringConstraints
)
from typing import Literal, Optional, Union, List, Annotated, Sequence
from datetime import datetime

"""
The api's chat interface is modeled after the OpenAI Chat Completion API:
https://platform.openai.com/docs/api-reference/chat

This schema expresses this API as Pydantic classes and should be considered the source of truth
of which parts of the Chap Completion API we support. 

"""

non_empty_string = Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1)
    ]
class ImageUrl(BaseModel):
    """
    Defines the structure for an image URL input.
    To simplify egress concerns, we don't supprt HTTPS urls at the moment.
    """
    model_config = ConfigDict(extra="ignore")

    url: str = Field(..., description="The base64 encoded image data URI.")
    detail: Optional[Literal["auto", "low", "high"]] = Field("auto", description="Specifies the detail level of the image.")

class FileContent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    file_data: Base64Bytes = Field(..., description="File data encoded as Base64 string")
    # these seem tied to OpenAI's file api. Most likely ignoring for now.
    file_id: Optional[str] = Field(default=None, description="The ID of an uploaded file to use as input")
    file_name: Optional[str] = Field(default=None, description="The name of the file, used when passing the file to the model as a string.")


class TextContentPart(BaseModel):
    """Represents a text part in a multimodal content list."""
    model_config = ConfigDict(extra="ignore")

    type: Literal["text"] = "text"
    text: non_empty_string

class FileContentPart(BaseModel):
    """Represents a file"""
    model_config = ConfigDict(extra="ignore")
    type: Literal["file"] = "file"
    file: FileContent

class ImageContentPart(BaseModel):
    """Represents an image part in a multimodal content list."""
    model_config = ConfigDict(extra="ignore")

    type: Literal["image_url"] = "image_url"
    image_url: ImageUrl

ContentPart = Union[TextContentPart, ImageContentPart, FileContentPart]

class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")

class UserMessage(Message):
    model_config = ConfigDict(extra="ignore")
    role: Literal["user"] = "user"
    content: Union[non_empty_string, Sequence[ContentPart]] = Field(description="The content of the message. Can be a string, a list of content parts (for multimodal input)")
    name: Optional[str] = None

class SystemMessage(Message):
    model_config = ConfigDict(extra="ignore")
    role: Literal["system"] = "system"
    content: Union[str, Sequence[TextContentPart]] = Field(description="The content of the message for the system. Can be a string, a list of text parts")
    name: Optional[str] = None


class AssistantMessage(Message):
    model_config = ConfigDict(extra="ignore")
    role: Literal["assistant"] = "assistant" 
    # TODO: refusals
    content: Union[str, Sequence[TextContentPart]] = Field(description="The content of the message from the model. Can be a string, a list of text parts")
    name: Optional[str] = None

ChatCompletionMessage = Annotated[
    Union[UserMessage, SystemMessage, AssistantMessage],
    Field(discriminator="role")
]
class ChatCompletionRequest(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "model": "gemini-2.0-flash",
                    "messages": [
                        {"role": "system","content": "You speak only pirate"},
                        {"role": "user","content": "Hello!"}
                    ]   
                }
            ]
        }
    }
    model: str = Field(..., description="The model to use for chat completion")
    messages: Sequence[ChatCompletionMessage] = Field(..., description="A list of messages from the conversation so far")
   
    temperature: Optional[Annotated[float, confloat(ge=0, le=2)]] = Field(
        default=None,
        description="What sampling temperature: between 0 and 2"
    )
    
    top_p: Optional[Annotated[float, confloat(ge=0, le=1)]] = Field(
        default=None,
        description="An alternative to sampling with temperature, called nucleus sampling"
    )
    
    n: Optional[int] = Field(
        default=None,
        description="How many chat completion choices to generate for each input message"
    )
    
    stream: Optional[bool] = Field(
        default=False,
        description="If set, partial message deltas will be sent"
    )
    
    stop: Optional[Union[str, List[str]]] = Field(
        default=None,
        description="Up to 4 sequences where the API will stop generating"
    )
    
    max_tokens: Optional[int] = Field(
        default=None,
        description="The maximum number of tokens to generate"
    )
    
    presence_penalty: Optional[Annotated[float, confloat(ge=-2.0, le=2.0)]] = Field(
        default=0,
        description="Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far"
    )
    
    frequency_penalty: Optional[Annotated[float, confloat(ge=-2.0, le=2.0)]]= Field(
        default=0,
        description="Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far"
    )
    
    logit_bias: Optional[dict[str, float]] = None
    user: Optional[str] = Field(
        default=None,
        description="A unique identifier representing your end-user"
    )

class ChatCompletionTokensDetails(BaseModel):
    # this is currently a stub, since it's in
    # the OpenAI spec, but there's no direct eqivelant 
    # in either bedrock or vertex
    accepted_prediction_tokens: int
    audio_tokens: int
    reasoning_tokens: int
    rejected_prediction_tokens: int
    
class ChatCompletionUsage(BaseModel):
    """Report of token use for a particular call"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

class ChatCompletionResponseMessage(BaseModel):
    """The LLM repsonse"""
    role: Literal["assistant"] = "assistant"
    content: str

class ChatCompletionChoice(BaseModel):
    index: NonNegativeInt
    message: ChatCompletionResponseMessage
    finish_reason: Optional[Literal["stop"]] = "stop"


class ChatCompletionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    object: Literal["chat.completion"] = "chat.completion"
    created: datetime
    model: str
    choices: List[ChatCompletionChoice]
    usage: ChatCompletionUsage
    
    @field_serializer('created')
    def serialize_dt(self, created: datetime, _info):
        return int(created.timestamp())


### Embedding Requests Model ###
class EmbeddingRequest(BaseModel):
    """
    Represents the request payload for the OpenAI Embeddings API.
    Reference: https://platform.openai.com/docs/api-reference/embeddings/create
    """
 
    input: Union[str, List[str]] = Field(
        ..., 
        description="Input text to embed, encoded as a string or array of strings. Each input must not exceed the max input tokens for the model."
    )
    model: str = Field(
        ...,
        description="ID of the model to use (e.g., 'text-embedding-3-small', 'text-embedding-ada-002')."
    )

    # openAI allows for base64 here too.
    # other provides have many other options. 
    # For now just stick with float
    encoding_format: Literal['float'] = Field(
        default='float',
        alias="encodingFormat", # deal with API's camelCase parameter
        description="The format to return the embeddings in. Currenly only 'float' is accepted."
    )
    dimensions: Optional[PositiveInt] = Field(
        default=None,
        description="The number of dimensions the resulting output embeddings should have. Only supported in some models."
    )
    user: Optional[str] = Field(
        default=None,
        description="A unique identifier representing your end-user, which can help OpenAI monitor and detect abuse."
    )
    # This is not part of the openAI spec.
    # Vertex and Cohere embeddings offer several options here:
    # TODO: how do we handle this? https://ai.google.dev/gemini-api/docs/embeddings#supported-task-types
    # For now accept a union of types and decide what to do in the conversion
    input_type: Optional[Literal[
        "search_document",        #vertex RETRIEVAL_DOCUMENT
        "search_query",           #vertex RETRIEVAL_QUERY
        "classification",
        "clustering",
        "semantic_similarity",
        ]] = Field(
        default=None,
        description="Not part of OpenAI spec, but is used in most other models. This allows the model to optimize for specific uses" 
    )
    model_config = ConfigDict(
        populate_by_name=True, 
        extra='ignore',
        json_schema_extra={
            "examples": [
                {
                    "input": "Narcotics cannot still the Tooth That nibbles at the soul",
                    "model": "cohere_english_v3",
                    "encodingFormat": "float",
                    "input_type": "search_document"
                }
            ]
        }
    )
  

# --- Embedding Response Models ---

class EmbeddingData(BaseModel):
    """
    A single embedding object within the response data array.
    """
    object: Optional[Literal["embedding"]] = Field(default="embedding", description="The object type, always 'embedding'.")
    embedding: Union[List[float], str] = Field(..., description="The embedding vector, which is a list of floats or a base64 string depending on 'encoding_format'.")
    index: int = Field(..., description="The index of the embedding in the list, corresponding to the input index.")

    model_config = ConfigDict(
        extra='ignore'
    )

class EmbeddingUsage(BaseModel):
    """
    Represents the token usage information for the embedding request.
    """
    prompt_tokens: int = Field(..., alias="promptTokens", description="The number of tokens in the prompt.")
    total_tokens: int = Field(..., alias="totalTokens", description="The total number of tokens used in the request (prompt + completion).")


    model_config = ConfigDict(
        populate_by_name=True, # Allows using aliases during instantiation from JSON
        extra='ignore'
    )

class EmbeddingResponse(BaseModel):
    """
    Represents the successful response payload from the OpenAI Embeddings API.
    See: https://platform.openai.com/docs/api-reference/embeddings/create
    """
    object: Optional[Literal["list"]] = Field(default="list", description="The object type, typically 'list'.")
    data: List[EmbeddingData] = Field(..., description="A list of embedding objects, one for each input.")
    model: str = Field(..., description="The ID of the model used for generating embeddings.")
    usage: EmbeddingUsage = Field(..., description="Usage statistics for the request.")


    model_config = ConfigDict(
        populate_by_name=True, # Needed for nested aliases (like EmbeddingUsage)
        extra='ignore'
    )
   

   # --- Stream Response Models ---

class StreamResponseDelta(BaseModel):
    content: Optional[str] = None
    refusal: Optional[str] = None
    role: Optional[str] = None

class StreamResponseChoice(BaseModel):
    delta: StreamResponseDelta
    finish_reason: Optional[str] = None
    index: int
class StreamResponse(BaseModel):
    id: str
    choices: List[StreamResponseChoice]
    model: str
    created: datetime
    object: Literal["chat.completion.chunk"] = "chat.completion.chunk"
    service_tier: Optional[str] = None
    system_fingerprint: str
    usage: Optional[ChatCompletionUsage] = None

    @field_serializer('created')
    def serialize_dt(self, created: datetime, _info):
        return int(created.timestamp())
