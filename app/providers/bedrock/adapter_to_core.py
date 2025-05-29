from datetime import datetime
from functools import singledispatch
from typing import Union, Iterator, AsyncGenerator, Any
import structlog

from ..core.chat_schema import ChatRepsonse, CompletionUsage, Response, StreamResponse, StreamResponseChoice, StreamResponseDelta
from ..core.embed_schema import EmbeddingResponse, EmbeddingData, EmbeddingUsage
from .converse_schemas import ConverseResponse, ConverseStreamChunk, MetadataEvent, MessageStartEvent, ContentBlockStartEvent, ContentBlockDeltaEvent, ContentBlockStopEvent, MessageStopEvent
from .cohere_embedding_schemas import CohereRepsonse

log = structlog.get_logger()

def bedrock_chat_response_to_core(resp: ConverseResponse, model:str) -> ChatRepsonse:
    return ChatRepsonse(
        model=model,
        created=datetime.now(),
        choices=[
            Response(content=r.text)
            for r in resp.output['message'].content
        ],
        usage=CompletionUsage(
            prompt_tokens=resp.usage.input_tokens,
            completion_tokens=resp.usage.output_tokens,
            total_tokens=resp.usage.total_tokens
        )
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
    # This can also be a tool call
    return _noop()

@_event_to_oai.register
def _(part: ContentBlockDeltaEvent) -> Iterator[RespPiece]:
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
        finish_reason=part.message_stop.stop_reason
    )

@_event_to_oai.register
def _(part: MetadataEvent) -> Iterator[RespPiece]:
    yield CompletionUsage(
            prompt_tokens=part.metadata.usage.input_tokens,
            completion_tokens=part.metadata.usage.output_tokens,
            total_tokens=part.metadata.usage.total_tokens,
    )

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