'''
Types for the Bedrock Converse API
https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_DocumentBlock.html

These are the destination types for conversions from public input appropriate for
passing to Bedrocks's converse() method as well as source types to convert back
to the output of the public API.
'''

from typing import Optional, Union, List, Literal, Dict, Any

from pydantic import BaseModel, Field, NonNegativeInt, ConfigDict, RootModel
from pydantic.alias_generators import to_camel



class ImageSource(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    # alias because pydantic does not allow python types as properties
    data: bytes = Field(..., description="Raw image data bytes.", alias="bytes")

class ImagePayload(BaseModel):
    format: Literal['jpeg', 'png', 'gif', 'webp'] = Field(..., description="Image format.")
    source: ImageSource

class ContentImageBlock(BaseModel):
    image: ImagePayload

class SystemContentBlock(BaseModel):
    # Bedrock allows other fields here that we're ignoring for now
    # https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_SystemContentBlock.html
    text: str

class ContentTextBlock(BaseModel):
    text: str

class DocumentSource(BaseModel):
    data: bytes = Field(..., description="Raw document data bytes.", alias="bytes")

class DocumentPayload(BaseModel):
    format: Literal['pdf', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'html', 'txt', 'md'] = Field(..., description="Document format.")
    name: str = Field(..., description="Name of the document.")
    source: DocumentSource

class ContentDocumentBlock(BaseModel):
    document: DocumentPayload

ContentBlock = Union[ContentTextBlock, ContentImageBlock, ContentDocumentBlock]

# it's not clear how to deal with OpenAI's other possible roles
BedrockMessageRole = Literal["user", "assistant"]

class Message(BaseModel):
    role: BedrockMessageRole
    content: List[ContentBlock]

class InferenceConfig(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel
    )
    max_tokens: Optional[int] = Field(default=None, description="Maximum number of tokens to generate")
    temperature: Optional[float] = Field(default=None, ge=0, le=1, description="Sampling temperature")
    top_p: Optional[float] = Field(default=None, ge=0, le=1, description="Top-p sampling")
    stop_sequences: Optional[List[str]] = Field(default=None, description="Optional list of stop sequences")

class ConverseRequest(BaseModel):
    model_config = ConfigDict(
        # Allows parsing input with either 'inference_config' or 'inferenceConfig'
        populate_by_name=True,
        alias_generator=to_camel
    )
    model_id: str = Field(..., exclude=True)
    messages: List[Message]
    system: Optional[List[SystemContentBlock]] = Field(default=None, description="Optional list of system prompts")
    inference_config: Optional[InferenceConfig] = Field(default=None, serialization_alias="inferenceConfig")

class ConverseResponseUsage(BaseModel):
    model_config = ConfigDict(
        # Allows parsing input with either 'inference_config' or 'inferenceConfig'
        populate_by_name=True,
        alias_generator=to_camel,
        extra="ignore"
    )
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    total_tokens: NonNegativeInt

class ConverseResponseOutput(BaseModel):
    role: Literal["assistant"]
    content: List[ContentTextBlock]

class ConverseResponse(BaseModel):
        output: dict[Literal["message"], ConverseResponseOutput]
        usage: ConverseResponseUsage

# ----- stream response ----

# --- Helper/Nested Models ---

class MessageStartContent(BaseModel):
    role: Literal["assistant"] # This will alway be "assistant" for responses

## Stubbing for later tool use
class ToolSpec(BaseModel):
    name: str
    input_schema: Dict[str, Any] = Field(alias="inputSchema") 

class ToolUseBlock(BaseModel):
    tool_use_id: str = Field(alias="toolUseId")
    name: str

class ContentBlockStartDetailsText(BaseModel):
    pass # Text start is often just an empty object, content comes in delta

class ContentBlockStartDetailsToolUse(BaseModel):
    tool_use_id: str = Field(alias="toolUseId")
    name: str

class ContentBlockStartStart(RootModel[Union[ContentBlockStartDetailsText, ContentBlockStartDetailsToolUse]]):
    pass

class ContentBlockStartContent(BaseModel):
    content_block_index: int = Field(alias="contentBlockIndex")
    start: Union[
        Dict[Literal["text"], ContentBlockStartDetailsText],
        Dict[Literal["toolUse"], ContentBlockStartDetailsToolUse]
    ] # The API uses the key ("text" or "toolUse") to discriminate




class ContentBlockDeltaDetailsToolUse(BaseModel):
    input: str # Tool input is typically a JSON string here


class ContentBlockDeltaContent(BaseModel):
    content_block_index: int = Field(alias="contentBlockIndex")
    delta: ContentTextBlock


class ContentBlockStopContent(BaseModel):
    content_block_index: int = Field(alias="contentBlockIndex")

class MessageStopContent(BaseModel):
    stop_reason: str = Field(alias="stopReason")
    additional_model_response_fields: Optional[Dict[str, Any]] = Field(
        default=None, alias="additionalModelResponseFields"
    )


class Metrics(BaseModel):
    latency_ms: Optional[int] = Field(default=None, alias="latencyMs")

class MetaDataContent(BaseModel):
    usage: ConverseResponseUsage
    metrics: Metrics
  
# --- Top-Level Event Models ---

class MessageStartEvent(BaseModel):
    message_start: MessageStartContent = Field(alias="messageStart")

class ContentBlockStartEvent(BaseModel):
    content_block_start: ContentBlockStartContent = Field(alias="contentBlockStart")

class ContentBlockDeltaEvent(BaseModel):
    content_block_delta: ContentBlockDeltaContent = Field(alias="contentBlockDelta")

class ContentBlockStopEvent(BaseModel):
    content_block_stop: ContentBlockStopContent = Field(alias="contentBlockStop")

class MessageStopEvent(BaseModel):
    message_stop: MessageStopContent = Field(alias="messageStop")

class MetadataEvent(BaseModel):
    metadata: MetaDataContent


# --- Error Models (Example) ---
class InternalServerExceptionContent(BaseModel):
    message: Optional[str] = None

class InternalServerExceptionEvent(BaseModel):
    internal_server_exception: InternalServerExceptionContent = Field(alias="internalServerException")

class ModelStreamErrorExceptionContent(BaseModel):
    message: Optional[str] = None
    original_status_code: Optional[int] = Field(default=None, alias="originalStatusCode")
    original_message: Optional[str] = Field(default=None, alias="originalMessage")

class ModelStreamErrorExceptionEvent(BaseModel):
    model_stream_error_exception: ModelStreamErrorExceptionContent = Field(alias="modelStreamErrorException")

class ValidationExceptionContent(BaseModel):
    message: Optional[str] = None

class ValidationExceptionEvent(BaseModel):
    validation_exception: ValidationExceptionContent = Field(alias="validationException")

# --- The Main Union Model for a single stream chunk ---
# This model represents that a chunk will be ONE of these event types.
ConverseStreamChunk = RootModel[
    Union[
        MessageStartEvent,
        ContentBlockStartEvent,
        ContentBlockDeltaEvent,
        ContentBlockStopEvent,
        MessageStopEvent,
        MetadataEvent,
        InternalServerExceptionEvent,
        ModelStreamErrorExceptionEvent,
        ValidationExceptionEvent
    ]
]