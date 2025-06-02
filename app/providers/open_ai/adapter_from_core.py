import structlog 

from ..core.chat_schema import ChatRepsonse, StreamResponse, ToolCall
from ..core.embed_schema import EmbeddingResponse as Core_EmbeddingResponse
import app.providers.open_ai.schemas as OA

log = structlog.get_logger()

def _tool_call_to_oa(tc: ToolCall) -> OA.ToolCall:
    return OA.ToolCall.model_validate(tc.model_dump())

def core_chat_response_to_openai(resp: ChatRepsonse) -> OA.ChatCompletionResponse:
    return OA.ChatCompletionResponse(
       model=resp.model,
       created=resp.created,
       choices=[
           OA.ChatCompletionChoice(
               index=idx,
               finish_reason=c.finish_reason,
               message=OA.ChatCompletionResponseMessage(
                    content=c.content,
                    tool_calls=[_tool_call_to_oa(tc) for tc in c.tool_calls] if c.tool_calls else None
                )
           ) for idx, c in enumerate(resp.choices)
       ],
       usage=OA.ChatCompletionUsage.model_validate(resp.usage, from_attributes=True)
    )

def core_embed_response_to_openai(resp: Core_EmbeddingResponse) -> OA.EmbeddingResponse:
    return OA.EmbeddingResponse(
        model=resp.model,
        data=[OA.EmbeddingData.model_validate(data, from_attributes=True) for data in resp.data],
        usage=OA.EmbeddingUsage.model_validate(resp.usage, from_attributes=True)
    )

def core_chat_chunk_to_openai(resp: StreamResponse) -> OA.StreamResponse:
    return OA.StreamResponse(
        id=resp.id ,
        model=resp.model,
        created=resp.created,
        choices=[OA.StreamResponseChoice.model_validate(choice.model_dump()) for choice in resp.choices],
        usage=OA.ChatCompletionUsage.model_validate(resp.usage.model_dump()) if resp.usage else None,
        system_fingerprint="123"
    )

async def convert_core_stream_openai(stream):
    async for chunk in stream:
        try:
            converted = core_chat_chunk_to_openai(chunk)
            yield f"data: {converted.model_dump_json(exclude_none=True)}\n\n"
        except Exception as e:
            # need to yield error to stream here
            log.error("error in convert:", e)
        
    yield "data: [DONE]\n\n"