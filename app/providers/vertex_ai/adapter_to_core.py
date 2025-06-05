from datetime import datetime
from typing import List, Optional, AsyncGenerator, Literal, Dict
from uuid import uuid4
import json

from ..core.chat_schema import ChatRepsonse, CompletionUsage, Response, StreamResponse, StreamResponseDelta, StreamResponseChoice, ToolCall, FunctionCall
from ..core.embed_schema import EmbeddingResponse, EmbeddingData, EmbeddingUsage
import vertexai.generative_models  as vtx 
from vertexai.language_models import TextEmbedding


def convert_chat_vertex_response(resp: vtx.GenerationResponse, model:str) -> ChatRepsonse:
        usage = CompletionUsage(
            prompt_tokens=resp.usage_metadata.prompt_token_count,
            completion_tokens=resp.usage_metadata.candidates_token_count,
            total_tokens=resp.usage_metadata.total_token_count, 
        )
        core_response_choices: List[Response] = []   

        for i, candidate in enumerate(resp.candidates):
            text_content_parts = []
            vertex_function_calls: List[vtx.FunctionCall] = []

            if candidate.content and candidate.content.parts:
                
                for part in candidate.content.parts:
                    if  hasattr(part, 'text'):
                        text_content_parts.append(part.text)
                    elif hasattr(part, 'function_call'):
                        vertex_function_calls.append(part.function_call)

            mapped_finish_reason = map_vertex_finish_reason_to_openai(candidate.finish_reason)
            
            if vertex_function_calls:
                # this apparently is possible with vertex
                if mapped_finish_reason != "tool_calls":
                    mapped_finish_reason = "tool_calls"
            
            final_text_content: Optional[str] = None
            
            if text_content_parts:
                final_text_content = "".join(text_content_parts)

            core_tool_calls_list: Optional[List[ToolCall]] = None
            if vertex_function_calls:
                core_tool_calls_list = []
                for idx, fc_from_vertex in enumerate(vertex_function_calls):
                    tool_call_id = f"call_{uuid4().hex[:10]}"
                    core_tool_calls_list.append(
                        ToolCall(
                            index=idx,
                            id=tool_call_id,
                            type="function",
                            function=FunctionCall(
                                name=fc_from_vertex.name,
                                arguments=json.dumps(fc_from_vertex.args) if fc_from_vertex.args else "{}"
                            ),
                        )
                    )
            
            core_response_choices.append(
                Response(
                    content=final_text_content,
                    tool_calls=core_tool_calls_list,
                    finish_reason=mapped_finish_reason
                )
            )

        
        
        return ChatRepsonse(
            created=datetime.now(),
            model=model,
            choices=core_response_choices,
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
    vtx.FinishReason.STOP: "stop",
    vtx.FinishReason.MAX_TOKENS: "length",
    vtx.FinishReason.SAFETY: "content_filter",
    vtx.FinishReason.RECITATION: "content_filter",
    vtx.FinishReason.BLOCKLIST: "content_filter",
    vtx.FinishReason.PROHIBITED_CONTENT: "content_filter",
    vtx.FinishReason.SPII: "content_filter",
    vtx.FinishReason.MALFORMED_FUNCTION_CALL: "content_filter",  
    vtx.FinishReason.OTHER: "stop",
    vtx.FinishReason.FINISH_REASON_UNSPECIFIED: None,
}   

def map_vertex_finish_reason_to_openai(
    vertex_reason: Optional[vtx.FinishReason],
) -> Literal['stop', 'length', 'tool_calls', 'content_filter'] | None:
    
    if vertex_reason is None:
        return None
    return stop_reason_map.get(vertex_reason)


async def vertex_stream_response_to_core(vertex_stream, model_id) ->  AsyncGenerator[StreamResponse, None]:
    sent_role_for_candidate_idx = set()
    stream_id = f"chatcmpl-{uuid4()}"

    created_timestamp = datetime.now()
    in_progress_args: Dict[int, Dict[str, str]] = {}  # candidate_idx -> {"id": str, "name": str, "args": str}


    input_tokens_total = 0
    output_tokens_total = 0

    async for vertex_response in vertex_stream:
        if vertex_response.usage_metadata:
            input_tokens_total += getattr(vertex_response.usage_metadata, "prompt_token_count", 0)
            output_tokens_total += getattr(vertex_response.usage_metadata, "candidates_token_count", 0)

        if not vertex_response.candidates:
            continue

        for cand_idx, cand in enumerate(vertex_response.candidates):
            # Send role chunk if it's the first *meaningful* chunk for this candidate
            # A meaningful chunk has content or a finish reason.
            # OpenAI expects some start close chunks to this can yield
            # more than one chunk for each vertex chunk
            parts = cand.content.parts if cand.content and cand.content.parts else []
            has_text = any(getattr(p, "text", None) for p in parts)
            has_fcall  = any(getattr(p, "function_call", None) for p in parts)
            meaningful = has_text or has_fcall or cand.finish_reason
            

            if cand_idx not in sent_role_for_candidate_idx and meaningful:
                role_delta = StreamResponseDelta(role="assistant")
                
                yield StreamResponse(
                    id=stream_id,
                    created=created_timestamp,
                    model=model_id,
                    choices=[StreamResponseChoice(index=cand_idx,
                                                  delta=role_delta,
                                                  finish_reason=None)],
                )
                sent_role_for_candidate_idx.add(cand_idx)


            # ───── text parts ─────
            if has_text:
                for p in parts:
                    txt = getattr(p, "text", None)
                    if txt:
                        yield StreamResponse(
                            id=stream_id,
                            created=created_timestamp,
                            model=model_id,
                            choices=[StreamResponseChoice(
                                index=cand_idx,
                                delta=StreamResponseDelta(content=txt),
                                finish_reason=None,
                            )],
                        )

            # ───── function-call parts ─────
            if has_fcall:
                for idx, p in enumerate(parts):
                    fcall = getattr(p, "function_call", None)
                    if not fcall:
                        continue

                    # build / update the in-progress state for incremental args
                    state = in_progress_args.get(idx)
                    if state is None:
                        state = {
                            "id": f"call_{uuid4().hex[:10]}",
                            "name": fcall.name,
                            "args": json.dumps(fcall.args or {}),
                        }
                        in_progress_args[cand_idx] = state
                    else:
                        # append/overwrite args if they grow over multiple chunks
                        state["args"] = json.dumps(fcall.args or {})

                    tool_call_delta = ToolCall(
                        index = idx,
                        id=state["id"],
                        type="function",
                        function=FunctionCall(
                            name=state["name"],
                            arguments=state["args"],
                        ),
                    )
                    yield StreamResponse(
                        id=stream_id,
                        created=created_timestamp,
                        model=model_id,
                        choices=[StreamResponseChoice(
                            index=cand_idx,
                            delta=StreamResponseDelta(tool_calls=[tool_call_delta]),
                            finish_reason=None,
                        )],
                    )

            # ───── finish-reason chunk ─────
            if cand.finish_reason:
                mapped_reason = map_vertex_finish_reason_to_openai(cand.finish_reason)

                # force "tool_calls" for any tool-call chunks
                if cand_idx in in_progress_args:
                    mapped_reason = "tool_calls"

                yield StreamResponse(
                    id=stream_id,
                    created=created_timestamp,
                    model=model_id,
                    choices=[StreamResponseChoice(
                        index=cand_idx,
                        delta=StreamResponseDelta(),    # empty delta per OpenAI spec
                        finish_reason=mapped_reason,
                    )],
                )
                # clean out cached state for this candidate
                in_progress_args.pop(cand_idx, None)

    # ───── final usage record ─────
    if input_tokens_total or output_tokens_total:
        yield StreamResponse(
            id=stream_id,
            created=created_timestamp,
            model=model_id,
            choices=[],
            usage=CompletionUsage(
                prompt_tokens=input_tokens_total,
                completion_tokens=output_tokens_total,
                total_tokens=input_tokens_total + output_tokens_total,
            ),
        )
