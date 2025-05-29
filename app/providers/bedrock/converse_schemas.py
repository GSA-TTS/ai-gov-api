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

class BaseBedrockModel(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel,
        # guarantee round-trips
        validate_assignment=True,
    )
## Basic Content Blocks ##

## Image Block
class ImageSource(BaseBedrockModel):
    # alias because pydantic does not allow python types as properties
    data: bytes = Field(..., description="Raw image data bytes.", alias="bytes")

class ImagePayload(BaseBedrockModel):
    format: Literal['jpeg', 'png', 'gif', 'webp'] = Field(..., description="Image format.")
    source: ImageSource

class ContentImageBlock(BaseBedrockModel):
    image: ImagePayload

## Document Block
class DocumentSource(BaseBedrockModel):
    data: bytes = Field(..., description="Raw document data bytes.", alias="bytes")

class DocumentPayload(BaseBedrockModel):
    format: Literal['pdf', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'html', 'txt', 'md'] = Field(..., description="Document format.")
    name: str = Field(..., description="Name of the document.")
    source: DocumentSource

class ContentDocumentBlock(BaseBedrockModel):
    document: DocumentPayload

## Plain Text
class ContentTextBlock(BaseBedrockModel):
    text: str

# System Block
class SystemContentBlock(BaseBedrockModel):
    # Bedrock allows other fields here that we're ignoring for now
    # https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_SystemContentBlock.html
    text: str


## Block fo passing tool results as json
class ContentJSONBlock(BaseBedrockModel):
    json_: Any = Field(alias='json',  serialization_alias='json')

## Tool results are a content type that appears in messages
## They also have a content list, but it can't be recursive
## so we need two unions.

ContentBlock = Union[ContentTextBlock, ContentImageBlock, ContentDocumentBlock]

# For tool use request from the model
class ToolUseBlock(BaseBedrockModel):
    tool_use_id: str
    name: str
    input: Dict[str, Any]

# For subsequent reuest when passing tool results back to model
class ToolResultBlock(BaseBedrockModel):
    tool_use_id: str 
    content: List[Union[ContentBlock, ContentJSONBlock]]   
    status: Literal["success", "error"] = "success"

# Message Level content can also contain tool blocks:
MessageContentBlock = Union[ContentBlock, ToolResultBlock]

# it's not clear how to deal with OpenAI's other possible roles
BedrockMessageRole = Literal["user", "assistant"]

class Message(BaseBedrockModel):
    role: BedrockMessageRole
    content: List[MessageContentBlock]

class InferenceConfig(BaseBedrockModel):
    max_tokens: Optional[int] = Field(default=None, description="Maximum number of tokens to generate")
    temperature: Optional[float] = Field(default=None, ge=0, le=1, description="Sampling temperature")
    top_p: Optional[float] = Field(default=None, ge=0, le=1, description="Top-p sampling")
    stop_sequences: Optional[List[str]] = Field(default=None, description="Optional list of stop sequences")

## -- Bedrock Tool Requuest -- ##

# The innermost bit – Bedrock just defines JSON here
# https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ToolInputSchema.html
class ToolInputSchema(BaseBedrockModel):
    json_: Dict[str, Any] =  Field(alias="json")

class ToolSpecification(BaseBedrockModel):
    name: str
    description: Optional[str] = None
    input_schema: ToolInputSchema

class ToolItem(BaseBedrockModel):
    tool_spec: ToolSpecification

ToolChoice = Union[Literal["auto", "any"], Dict[Literal["tool"], Dict[str, str]]]
class ToolConfig(BaseBedrockModel):
    tools: List[ToolItem]
    tool_choice: Optional[ToolChoice] = None


class ConverseRequest(BaseBedrockModel):
    model_id: str = Field(..., exclude=True)
    messages: List[Message]
    system: Optional[List[SystemContentBlock]] = Field(default=None, description="Optional list of system prompts")
    inference_config: Optional[InferenceConfig] = Field(default=None, serialization_alias="inferenceConfig")
    tool_config: Optional[ToolConfig] = Field(default=None, alias="toolConfig")


class ConverseResponseUsage(BaseBedrockModel):
    model_config = ConfigDict(
        extra="ignore"
    )
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    total_tokens: NonNegativeInt

class ConverseResponseOutput(BaseBedrockModel):
    model_config = ConfigDict(extra="allow")
    role: Literal["assistant"]
    content: List[Union[ContentTextBlock, ToolUseBlock]]

class ConverseResponse(BaseBedrockModel):
        output: dict[Literal["message"], ConverseResponseOutput]
        usage: ConverseResponseUsage

# ----- stream response ----

# --- Helper/Nested Models ---

class MessageStartContent(BaseBedrockModel):
    role: Literal["assistant"] # This will alway be "assistant" for responses

 
class ContentBlockStartDetailsText(BaseBedrockModel):
    pass # Text start is often just an empty object, content comes in delta

class ContentBlockStartDetailsToolUse(BaseBedrockModel):
    tool_use_id: str
    name: str

class ContentBlockStartContent(BaseBedrockModel):
    content_block_index: int
    start: Union[
        Dict[Literal["text"], ContentBlockStartDetailsText],
        Dict[Literal["toolUse"], ContentBlockStartDetailsToolUse]
    ] # The API uses the key ("text" or "toolUse") to discriminate


class ContentBlockDeltaDetailsToolUse(BaseBedrockModel):
    input: str # Tool input is typically a JSON string here

class ContentBlockDeltaToolUse(BaseBedrockModel):

    tool_use: ContentBlockDeltaDetailsToolUse
    
class ContentBlockDeltaContent(BaseBedrockModel):
    content_block_index: int
    delta: Union[ContentTextBlock, ContentBlockDeltaToolUse]

class ContentBlockStopContent(BaseBedrockModel):
    content_block_index: int

class MessageStopContent(BaseBedrockModel):
    stop_reason: str
    additional_model_response_fields: Optional[Dict[str, Any]] = None


class Metrics(BaseBedrockModel):
    latency_ms: Optional[int] = None

class MetaDataContent(BaseBedrockModel):
    usage: ConverseResponseUsage
    metrics: Metrics
  
# --- Top-Level Event Models ---

class MessageStartEvent(BaseBedrockModel):
    message_start: MessageStartContent

class ContentBlockStartEvent(BaseBedrockModel):
    content_block_start: ContentBlockStartContent 

class ContentBlockDeltaEvent(BaseBedrockModel):
    content_block_delta: ContentBlockDeltaContent

class ContentBlockStopEvent(BaseBedrockModel):
    content_block_stop: ContentBlockStopContent

class MessageStopEvent(BaseBedrockModel):
    message_stop: MessageStopContent

class MetadataEvent(BaseBedrockModel):
    metadata: MetaDataContent


# --- Error Models (Example) ---
class InternalServerExceptionContent(BaseBedrockModel):
    message: Optional[str] = None

class InternalServerExceptionEvent(BaseBedrockModel):
    internal_server_exception: InternalServerExceptionContent

class ModelStreamErrorExceptionContent(BaseBedrockModel):
    message: Optional[str] = None
    original_status_code: Optional[int] = None
    original_message: Optional[str] = None

class ModelStreamErrorExceptionEvent(BaseBedrockModel):
    model_stream_error_exception: ModelStreamErrorExceptionContent

class ValidationExceptionContent(BaseBedrockModel):
    message: Optional[str] = None

class ValidationExceptionEvent(BaseBedrockModel):
    validation_exception: ValidationExceptionContent

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