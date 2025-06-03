from typing import List, cast, Sequence, Optional
from functools import singledispatch
from ..core.chat_schema import (
    AssistantMessage,
    ChatRequest,
    ContentPart,
    FilePart,
    ImagePart,
    Message,
    SystemMessage,
    ToolCall,
    ToolDefinition,
    ToolMessage,
    TextPart,
    UserMessage,
)
from ..core.embed_schema import EmbeddingRequest
import app.providers.open_ai.schemas as OA 
from app.providers.utils import parse_data_uri

## Handle Subparts of Message
@singledispatch
def _part_to_ir(part) -> ContentPart:
    raise TypeError(f"No converter for {type(part)}")

@_part_to_ir.register
def _(part: str) -> TextPart:
    return TextPart(text=part)

@_part_to_ir.register
def _(part: OA.TextContentPart) -> TextPart:
    return TextPart(text=part.text)

@_part_to_ir.register
def _(part: OA.ImageContentPart) -> ImagePart:
    image_data = parse_data_uri(part.image_url.url)
    return ImagePart(
        bytes=image_data['data'],
        file_type=image_data['format']
    )

@_part_to_ir.register
def _(part: OA.FileContentPart) -> FilePart:
    return FilePart(
        bytes=part.file.file_data,
        mime_type="application/pdf", # TODO determin mime type for file
        name=part.file.file_name
        )

## Handle Messages
@singledispatch
def _message_to_ir(message) -> Message:
    raise TypeError(f"No converter for {type(message)}")

@_message_to_ir.register
def _(message: OA.UserMessage) -> UserMessage:
    return UserMessage(
        role=message.role,
        content=convert_content(message.content)
    )

@_message_to_ir.register
def _(message: OA.SystemMessage) -> SystemMessage:
    return SystemMessage(
        # OA.SystemMessage can only have text parts
        content=cast(List[TextPart], convert_content(message.content))
    )

@_message_to_ir.register
def _(message: OA.AssistantMessage) -> AssistantMessage:
    return AssistantMessage(
        content=convert_content(message.content),
        tool_calls=[_tool_call_to_ir(tc) for tc in message.tool_calls] if message.tool_calls else None
    )

@_message_to_ir.register
def _(message: OA.ToolMessage) -> ToolMessage:
    return ToolMessage(
        tool_call_id=message.tool_call_id,
        content=convert_text(message.content)
    )

@singledispatch
def _tool_def_to_ir(td) -> ToolDefinition:
    raise TypeError(f"No converter for {type(td)}")

@_tool_def_to_ir.register
def _(td: OA.ToolDefinition) -> ToolDefinition:
    # identical JSON layout → model_dump / model_validate is simplest
    return ToolDefinition.model_validate(td.model_dump())

def _tool_call_to_ir(tc: OA.ToolCall) -> ToolCall:
    return ToolCall.model_validate(tc.model_dump())

def convert_text(content: Optional[str | Sequence[OA.TextContentPart]]) -> List[TextPart]:
    if content is None: 
        return []
    return [TextPart(text=content)] if isinstance(content, str) else [TextPart(text=m.text) for m in content]

def convert_content(content: str | Sequence[OA.ContentPart] | None) -> List[ContentPart]:
    if content is None:
        return []
    if isinstance(content, str):
        return [TextPart(text=content)]
    return [_part_to_ir(p) for p in content]


def openai_chat_request_to_core(req: OA.ChatCompletionRequest) -> ChatRequest:
    return ChatRequest(
        model=req.model,
        temperature=req.temperature,
        top_p=req.top_p,
        max_tokens=req.max_tokens,
        stream=req.stream,
        stop=[req.stop] if isinstance(req.stop, str) else req.stop,
        messages=[_message_to_ir(m) for m in req.messages],
        tools=[_tool_def_to_ir(tool) for tool in req.tools] if req.tools else None,
        tool_choice=req.tool_choice,
    )


def openai_embed_request_to_core(req: OA.EmbeddingRequest) -> EmbeddingRequest:
    return EmbeddingRequest(
        model=req.model,
        input=[req.input] if isinstance(req.input, str) else req.input,
        encoding_format=req.encoding_format,
        input_type=req.input_type,
        dimensions = req.dimensions,

    )   

