from datetime import datetime
import json
from functools import singledispatch
from typing import Union, Iterator, AsyncGenerator, Any, Literal
import structlog

from ..exceptions import (
    BedrockUnavailable,
    BedrockValidationError
)
from ..core.chat_schema import (
    ChatRepsonse,
    CompletionUsage,
    FunctionCall,
    Response,
    StreamResponse,
    StreamResponseChoice,
    StreamResponseDelta,
    ToolCall
)
from ..core.embed_schema import EmbeddingResponse, EmbeddingData, EmbeddingUsage
from .converse_schemas import (
    ContentTextBlock,
    ConverseResponse,
    ConverseStreamChunk,
    ContentBlockDeltaToolUse,
    MetadataEvent,
    MessageStartEvent,
    ContentBlockStartEvent,
    ContentBlockDeltaEvent,
    ContentBlockStopEvent,
    MessageStopEvent,
    StartToolUse,
    ToolUseBlock,
    InternalServerExceptionEvent,
    ModelStreamErrorExceptionEvent,
    ValidationExceptionEvent
)
from .cohere_embedding_schemas import CohereRepsonse

log = structlog.get_logger()


def bedrock_tool_use_to_core(tu: ToolUseBlock) -> ToolCall:
    return ToolCall(
        index=None,
        id=tu.tool_use.tool_use_id,
        function=FunctionCall(
            name=tu.tool_use.name,
            arguments=json.dumps(tu.tool_use.input),
        )
    )

def map_bedrock_stop_reason(sr: str | None) -> Literal['stop', 'length', 'tool_calls', 'content_filter'] | None:
    """
    Convert Bedrock stopReason → Core finish_reason.
    """
    if sr is None:
        return None
    match sr:
        case "stop_sequence" | "end_turn":
            return "stop"
        case "max_tokens":
            return "length"
        case "tool_use":
            return "tool_calls"
        case _:
            return "stop"



def bedrock_chat_response_to_core(resp: ConverseResponse, model: str) -> ChatRepsonse:
    choice = Response(content="")

    for block in resp.output["message"].content:
        if isinstance(block, ContentTextBlock):
            choice.content = (choice.content or "") + block.text

        elif isinstance(block, ToolUseBlock):
            converted = bedrock_tool_use_to_core(block)
            choice.tool_calls = (choice.tool_calls or []) + [converted]

        # (Optional) ignore other block types like ToolResultBlock,
        # because tool replies appear only in *requests*.
    choice.finish_reason = map_bedrock_stop_reason(resp.stop_reason)
    # Not sure if this can happen but if Bedrock ever sent neither text nor tool call,
    # `core_choices` will stay empty; OpenAI expects at least one choice,
    # so create an empty shell:

    return ChatRepsonse(
        model=model,
        created=datetime.now(),
        choices=[choice],
        usage=CompletionUsage(
            prompt_tokens=resp.usage.input_tokens,
            completion_tokens=resp.usage.output_tokens,
            total_tokens=resp.usage.total_tokens,
        ),
    )
def bedorock_embed_reposonse_to_core(resp: CohereRepsonse, model:str, token_count) -> EmbeddingResponse:
    return EmbeddingResponse(
        model=model,
        data=[EmbeddingData(index=idx, embedding=data) for idx, data in enumerate(resp.embeddings['float'])],
        usage=EmbeddingUsage(prompt_tokens=token_count, total_tokens=token_count)
    )


# --------- Handle the menagerie of stream chunk types
RespPiece = Union[StreamResponseChoice, CompletionUsage] 

def _noop() -> Iterator[RespPiece]:
    return iter(())


@singledispatch
def _event_to_oai(part: ConverseStreamChunk) -> Iterator[RespPiece]:
    log.warning(f"Unhandled Bedrock event:{type(part)}")
    return _noop()

@_event_to_oai.register
def _(part: MessageStartEvent) -> Iterator[RespPiece]:
    yield StreamResponseChoice(
        index=0,
        delta=StreamResponseDelta(
            role="assistant",
            content=""
        )
    )

@_event_to_oai.register
def _(part: ContentBlockStartEvent) -> Iterator[RespPiece]:
    openai_tool_call_idx = part.content_block_start.content_block_index
    start = part.content_block_start.start
    if isinstance(start, StartToolUse):
        details =start.tool_use
        yield StreamResponseChoice(
            index=0,
            delta=StreamResponseDelta(
                tool_calls=[ToolCall(
                    index=openai_tool_call_idx,
                    id=details.tool_use_id,
                    function=FunctionCall(
                        name=details.name,
                        arguments=""   # start empty
                    )
                )]
            )
        )
    return _noop()

@_event_to_oai.register
def _(part: ContentBlockDeltaEvent) -> Iterator[RespPiece]:
    openai_tool_call_idx = part.content_block_delta.content_block_index

    if isinstance(part.content_block_delta.delta, ContentBlockDeltaToolUse):
        yield StreamResponseChoice(
            index=0,
            delta=StreamResponseDelta(
                tool_calls=[ToolCall(
                    index=openai_tool_call_idx,  
                    # omit id in subsequent calls  
                    function=FunctionCall(
                        arguments=part.content_block_delta.delta.tool_use.input
                    )
                )]
            )
        )
    elif isinstance(part.content_block_delta.delta, ContentTextBlock):
        yield StreamResponseChoice(
            index=0,
            delta=StreamResponseDelta(
                content=part.content_block_delta.delta.text
            )
        )

@_event_to_oai.register
def _(part: ContentBlockStopEvent) -> Iterator[RespPiece]:
   return _noop()
   
@_event_to_oai.register
def _(part: MessageStopEvent) -> Iterator[RespPiece]:
    yield StreamResponseChoice(
        index=0,
        delta=StreamResponseDelta(),
        finish_reason=map_bedrock_stop_reason(part.message_stop.stop_reason)
    )

@_event_to_oai.register
def _(part: MetadataEvent) -> Iterator[RespPiece]:
    yield CompletionUsage(
            prompt_tokens=part.metadata.usage.input_tokens,
            completion_tokens=part.metadata.usage.output_tokens,
            total_tokens=part.metadata.usage.total_tokens,
    )

## stream exception events
@_event_to_oai.register
def _(ev: InternalServerExceptionEvent) -> Iterator[RespPiece]:
    raise BedrockUnavailable(ev.internal_server_exception.message or
                             "Internal error from Bedrock")

@_event_to_oai.register
def _(ev: ModelStreamErrorExceptionEvent) -> Iterator[RespPiece]:
    raise BedrockUnavailable(ev.model_stream_error_exception.message or
                             "Stream error from model")

@_event_to_oai.register
def _(ev: ValidationExceptionEvent) -> Iterator[RespPiece]:
    raise BedrockValidationError(ev.validation_exception.message or
                                 "Validation error in streaming request")


async def bedrock_chat_stream_response_to_core(bedrockStream, model:str, id:str) -> AsyncGenerator[StreamResponse, Any]: 
    usage = None
    async for stream_event in bedrockStream:
        resp = ConverseStreamChunk.model_validate(stream_event)
        
        for event in _event_to_oai(resp.root):
            if isinstance(event, CompletionUsage): 
                # A bedrock usage event does not necessarily come last
                # buffer the usage and send it after MessageStop
                usage = event
            else:
                yield StreamResponse(
                    id=id,
                    object="chat.completion.chunk",
                    model=model,
                    created=datetime.now(),
                    choices=[event],
                )
    if usage is not None:
        yield StreamResponse(
            id=id,
            object="chat.completion.chunk",
            model=model,
            created=datetime.now(),
            choices=[],
            usage=usage
            )