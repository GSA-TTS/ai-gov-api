from typing import List, cast, Sequence
from functools import singledispatch
from ..core.chat_schema import (
    ChatRequest,
    ContentPart,
    Message,
    SystemMessage,
    AssistantMessage,
    UserMessage,
    TextPart,
    ImagePart,
    FilePart
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
        mime_type="application/pdf" # TODO determin mime type for file
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
        content=convert_content(message.content)
    )

def convert_content(content: str | Sequence[OA.ContentPart]) -> List[ContentPart]:
    return [TextPart(text=content)] if isinstance(content, str) else [_part_to_ir(m) for m in content]

def openai_chat_request_to_core(req: OA.ChatCompletionRequest) -> ChatRequest:
    return ChatRequest(
        model=req.model,
        temperature=req.temperature,
        top_p=req.top_p,
        max_tokens=req.max_tokens,
        stream=req.stream,
        stop=[req.stop] if isinstance(req.stop, str) else req.stop,
        messages=[_message_to_ir(m) for m in req.messages],
    )


def openai_embed_request_to_core(req: OA.EmbeddingRequest) -> EmbeddingRequest:
    return EmbeddingRequest(
        model=req.model,
        input=[req.input] if isinstance(req.input, str) else req.input,
        encoding_format=req.encoding_format,
        input_type=req.input_type,
        dimensions = req.dimensions,

    )   

