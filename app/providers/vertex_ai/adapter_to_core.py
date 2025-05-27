from datetime import datetime
from typing import List, Optional, AsyncGenerator
from uuid import uuid4

from ..core.chat_schema import ChatRepsonse, CompletionUsage, Response, StreamResponse, StreamResponseDelta, StreamResponseChoice
from ..core.embed_schema import EmbeddingResponse, EmbeddingData, EmbeddingUsage
from vertexai.generative_models import GenerationResponse, FinishReason
from vertexai.language_models import TextEmbedding


def convert_chat_vertex_response(resp: GenerationResponse, model:str) -> ChatRepsonse:
        usage = CompletionUsage(
            prompt_tokens=resp.usage_metadata.prompt_token_count,
            completion_tokens=resp.usage_metadata.candidates_token_count,
            total_tokens=resp.usage_metadata.total_token_count, 
        )   
        choices = [Response(content=candidate.content.parts[0].text) for i, candidate in enumerate(resp.candidates)]
        
        return ChatRepsonse(
            created=datetime.now(),
            model=model,
            choices=choices,
            usage=usage
        )

def vertex_embed_reposonse_to_core(embeddings: List[TextEmbedding], model:str) -> EmbeddingResponse:
    token_count = sum(int(emb.statistics.token_count) for emb in embeddings if emb.statistics)
    usage = EmbeddingUsage(
        prompt_tokens=token_count,
        total_tokens=token_count
    )
    return EmbeddingResponse(
        model=model,
        data=[EmbeddingData(index=idx, embedding=data.values) for idx, data in enumerate(embeddings)],
        usage=usage
    )

stop_reason_map = {
    FinishReason.STOP: "stop",
    FinishReason.MAX_TOKENS: "length",
    FinishReason.SAFETY: "content_filter",
    FinishReason.RECITATION: "content_filter",
    FinishReason.OTHER: "stop"
}   

def map_vertex_finish_reason_to_openai(
    vertex_reason: Optional[FinishReason],
) -> Optional[str]:
    
    if vertex_reason is None:
        return None
    return stop_reason_map.get(vertex_reason)


async def vertex_stream_response_to_core(vertex_stream, model_id) ->  AsyncGenerator[StreamResponse, None]:
    sent_role_for_candidate_idx = set()
    stream_id = f"chatcmpl-{uuid4()}"

    created_timestamp = datetime.now()
    input_tokens_total = 0
    output_tokens_total = 0

    async for vertex_response in vertex_stream:
        if vertex_response.usage_metadata:
            input_tokens_total += getattr(vertex_response.usage_metadata, "prompt_token_count", 0)
            output_tokens_total += getattr(vertex_response.usage_metadata, "candidates_token_count", 0)

        if not vertex_response.candidates:
            continue
        for candidate_idx, candidate in enumerate(vertex_response.candidates):
            # Send role chunk if it's the first *meaningful* chunk for this candidate
            # A meaningful chunk has content or a finish reason.
            # OpenAI expects some start close chunks to this can yield
            # more than one chunk for each vertex chunk
            has_content = (
                candidate.content
                and candidate.content.parts
                and hasattr(candidate.content.parts[0], 'text') # Ensure it's a text part
                and candidate.content.parts[0].text
            )

            if candidate_idx not in sent_role_for_candidate_idx and (has_content or candidate.finish_reason):
                role_delta = StreamResponseDelta(role="assistant")
                choice = StreamResponseChoice(index=candidate_idx, delta=role_delta, finish_reason=None)
                yield StreamResponse(
                    id=stream_id,
                    created=created_timestamp,
                    model=model_id,
                    choices=[choice],
                )

                sent_role_for_candidate_idx.add(candidate_idx)

            # A content chunk(s)
            if has_content:
                for part in candidate.content.parts:
                    if hasattr(part, 'text') and part.text:
                        content_delta = StreamResponseDelta(content=part.text)
                        choice = StreamResponseChoice(index=candidate_idx, delta=content_delta, finish_reason=None)
                        yield StreamResponse(
                            id=stream_id,
                            created=created_timestamp,
                            model=model_id,
                            choices=[choice],
                        )
            
            # A finish reason chunk
            if candidate.finish_reason:
                openai_finish_reason = map_vertex_finish_reason_to_openai(candidate.finish_reason)
                # Delta can be empty if only finish_reason is present, or content can be null
                # OpenAI clients expect an empty delta or a delta with null content.
                finish_delta = StreamResponseDelta() # Empty delta
                choice = StreamResponseChoice(
                    index=candidate_idx,
                    delta=finish_delta,
                    finish_reason=openai_finish_reason,
                )
                yield StreamResponse(
                    id=stream_id,
                    created=created_timestamp,
                    model=model_id,
                    choices=[choice],
                )
    if input_tokens_total or output_tokens_total:
        yield StreamResponse(
            id=stream_id,
            created=created_timestamp,
            model=model_id,
            choices=[], 
            usage= CompletionUsage(
                prompt_tokens=input_tokens_total,
                completion_tokens=output_tokens_total,
                total_tokens=input_tokens_total + output_tokens_total,
            ),
        )
