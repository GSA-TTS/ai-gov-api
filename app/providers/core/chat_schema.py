'''
This is an intermediate format representing an abstract chat request.
It's purpose it to insulate from changes to the OpenAI API and prevent
re-writing conversion code.

Other provides should provide adapters for converting to and from this schema
and should never "know" about other provider formats (including OpenAI's).

OpenAI requests will be converted into this form and wll concrete representations
should convert from this.

                  |-> Bedrock
OpenAI -> Core -> |-> Vertex
                  |-> Others
'''
from datetime import datetime
from typing import Literal, Annotated, Optional, List, Any, Sequence
from pydantic import BaseModel, Field, BeforeValidator

def convert_str(value: Any) -> Any:  
    if isinstance(value, str):  
        return [{"type":"text", "text": value}]
    else:
        return value


# ----> Chat Request Model <---- #
class TextPart(BaseModel):
    type: Literal["text"] = "text"
    text: str

class ImagePart(BaseModel):
    type: Literal["image", "image_url"] = "image"
    file_type: Literal['jpeg', 'png', 'gif', 'webp']
    bytes_: bytes = Field(..., alias="bytes")

class FilePart(BaseModel):
    type: Literal["file"] = "file"
    mime_type: str
    bytes_: bytes = Field(..., alias="bytes")

ContentPart = Annotated[TextPart | ImagePart | FilePart, Field(discriminator="type")]
class UserMessage(BaseModel):
    role: Literal["user"] = "user"  
    content: Annotated[Sequence[ContentPart], BeforeValidator(convert_str)]

class AssistantMessage(BaseModel):
    role: Literal["assistant"] = "assistant"  
    content: Annotated[Sequence[ContentPart], BeforeValidator(convert_str)]

class SystemMessage(BaseModel):
    role: Literal['system'] = "system"
    content: Annotated[Sequence[TextPart], BeforeValidator(convert_str)]

Message = Annotated[UserMessage | AssistantMessage | SystemMessage, Field(discriminator="role")]

class ChatRequest(BaseModel):
    model: str
    messages: Sequence[Message]
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
    stop: Optional[List[str]] = None



# ----> Chat Response Model <---- #
# This is almost identical to the OpenAI
# repsonse model. Keeping it seperate
# to maintain an layer of abstraction
class Response(BaseModel):
    content: str
    
class CompletionUsage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

class ChatRepsonse(BaseModel):
    created: datetime
    model: str
    choices: List[Response]
    usage: CompletionUsage


# ----> Chat Response Model <---- #

class StreamResponseDelta(BaseModel):
    content: Optional[str] = None
    refusal: Optional[str] = None
    role: Optional[str] = None

class StreamResponseChoice(BaseModel):
    delta: Optional[StreamResponseDelta] = None
    finish_reason: Optional[str] = None
    index: int
class StreamResponse(BaseModel):
    id: str
    choices: List[StreamResponseChoice]
    model: str
    created: datetime
    object: Literal["chat.completion.chunk"] = "chat.completion.chunk"
    service_tier: Optional[str] = None
    usage: Optional[CompletionUsage] = None