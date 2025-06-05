import pytest
from uuid import UUID
from datetime import datetime
import app.providers.core.chat_schema as core
from app.providers.vertex_ai.adapter_to_core import vertex_stream_response_to_core
from vertexai.generative_models import FinishReason

# -- Mocks --

class MockPart:
    def __init__(self, text=None):
        self.text = text

class MockContent:
    def __init__(self, parts):
        self.parts = parts

class MockCandidate:
    def __init__(self, text=None, finish_reason=None):
        self.content = MockContent([MockPart(text)] if text else [])
        self.finish_reason = finish_reason

class MockVertexUsage:
    def __init__(self, input_tokens, output_tokens):
        self.prompt_token_count = input_tokens
        self.candidates_token_count = output_tokens
class MockVertexResponse:
    def __init__(self, candidates, usage=None):
        self.candidates = candidates
        self.usage_metadata = usage

async def make_stream(responses):
    for r in responses:
        yield r

@pytest.mark.asyncio
async def test_single_content_chunk_with_role_and_finish_reason():
    vertex_stream = make_stream([
        MockVertexResponse([
            MockCandidate(text="Hello", finish_reason=FinishReason.STOP)
        ])
    ])
    results:list[core.StreamResponse] = [resp async for resp in vertex_stream_response_to_core(vertex_stream, model_id="vertex-ai-001")]

    assert len(results) == 3

    role_chunk = results[0]
    assert role_chunk.choices[0].delta is not None
    assert role_chunk.choices[0].delta.role == "assistant"

    content_chunk = results[1]
    assert content_chunk.choices[0].delta is not None
    assert content_chunk.choices[0].delta.content == "Hello"

    finish_chunk = results[2]
    assert finish_chunk.choices[0].finish_reason == "stop" 
    assert finish_chunk.choices[0].delta is not None
    assert finish_chunk.choices[0].delta.model_dump(exclude_none=True) == {}

    for r in results:
        assert UUID(r.id.replace("chatcmpl-", ""), version=4)
        assert isinstance(r.created, datetime)


@pytest.mark.asyncio
async def test_ignores_empty_candidates():
    vertex_stream = make_stream([
        MockVertexResponse([MockCandidate()])
    ])
    results = [r async for r in vertex_stream_response_to_core(vertex_stream, "model")]

    assert results == []


@pytest.mark.asyncio
async def test_multiple_candidates_and_index_tracking():
    vertex_stream = make_stream([
        MockVertexResponse([
            MockCandidate(text="First", finish_reason=None),
            MockCandidate(text="Second", finish_reason="STOP")
        ])
    ])
    results = [r async for r in vertex_stream_response_to_core(vertex_stream, "model")]

    # Expecting:
    # 0: role chunk for idx 0
    # 1: content chunk for idx 0
    # 2: role chunk for idx 1
    # 3: content chunk for idx 1
    # 4: finish chunk for idx 1
    roles = [r for r in results if r.choices[0].delta is not None and r.choices[0].delta.role == "assistant"]
    assert len(roles) == 2
    assert [r.choices[0].index for r in roles] == [0, 1]


@pytest.mark.asyncio
async def test_multiple_parts_in_candidate():
    class MultiPartCandidate:
        def __init__(self):
            self.content = MockContent([
                MockPart("Hello"), MockPart(" world")
            ])
            self.finish_reason = None

    vertex_stream = make_stream([
        MockVertexResponse([MultiPartCandidate()])
    ])
    results = [r async for r in vertex_stream_response_to_core(vertex_stream, "model")]

    contents = [r.choices[0].delta.content for r in results if r.choices[0].delta is not None and r.choices[0].delta.content]
    assert contents == ["Hello", " world"]  


@pytest.mark.asyncio
async def test_usage_collections():
    vertex_stream = make_stream([
        MockVertexResponse(
            [MockCandidate()],
            usage=MockVertexUsage(input_tokens=2, output_tokens=3)
        )
    ])
    results = [r async for r in vertex_stream_response_to_core(vertex_stream, "model")]

    assert results[-1].usage is not None
    assert results[-1].usage.prompt_tokens == 2
    assert results[-1].usage.completion_tokens == 3
    assert results[-1].usage.total_tokens == 5


# For function-calling chunks

class MockFunctionCall:
    def __init__(self, name: str, args: dict | None = None):
        self.name = name
        self.args = args or {}

class MockPartWithCall(MockPart):
    """Inherits text-part stub but carries a Vertex FunctionCall."""
    def __init__(self, name: str, args: dict | None = None):
        super().__init__(text=None)
        self.function_call = MockFunctionCall(name, args)



@pytest.mark.asyncio
async def test_single_tool_call_chunk():
    """Vertex streams one chunk containing a complete function_call."""

    cand = MockCandidate(text=None, finish_reason=FinishReason.STOP)
    cand.content = MockContent([MockPartWithCall("get_weather", {"city": "Paris"})])

    vertex_stream = make_stream([MockVertexResponse([cand])])
    results = [
        r async for r in vertex_stream_response_to_core(
            vertex_stream, model_id="vertex-ai-001"
        )
    ]

    # Expect: role - tool_call delta - finish-reason delta
    assert len(results) == 3

    role_chunk, call_chunk, finish_chunk = results

    # role chunk
    assert role_chunk.choices[0].delta.role == "assistant" # type: ignore

    # tool_call delta
    tc_delta = call_chunk.choices[0].delta.tool_calls # type: ignore
    assert tc_delta and len(tc_delta) == 1
    tc = tc_delta[0]
    assert tc.type == "function"
    assert tc.function.name == "get_weather"
    assert tc.function.arguments == '{"city": "Paris"}'

    # finish reason forced to "tool_calls"
    assert finish_chunk.choices[0].finish_reason == "tool_calls"



@pytest.mark.asyncio
async def test_tool_call_multi_chunk_id_and_args_growth():
    """
    Vertex streams the same function call in two chunks:
    - first with empty args, second with full args and the finish reason.
    We should reuse the same tool_call.id across deltas.
    """

    chunk1_cand = MockCandidate(text=None, finish_reason=None)
    chunk1_cand.content = MockContent([MockPartWithCall("get_weather", {})])

    chunk2_cand = MockCandidate(text=None, finish_reason=FinishReason.STOP)
    chunk2_cand.content = MockContent([MockPartWithCall("get_weather", {"city": "Berlin"})])

    vertex_stream = make_stream([
        MockVertexResponse([chunk1_cand]),
        MockVertexResponse([chunk2_cand])
    ])

    results = [
        r async for r in vertex_stream_response_to_core(vertex_stream, "vertex-ai-001")
    ]

    # We should see: role, first tool_call, second tool_call (updated args), finish
    assert len(results) == 4

    # Grab both tool_call deltas
    tc1 = results[1].choices[0].delta.tool_calls[0]  # type: ignore
    tc2 = results[2].choices[0].delta.tool_calls[0] # type: ignore

    # 1️⃣ IDs stay identical across chunks
    assert tc1.id == tc2.id

    # 2️⃣ First args {}, second args {"city": "Berlin"}
    assert tc1.function.arguments == "{}"
    assert tc2.function.arguments == '{"city": "Berlin"}'

    # 3️⃣ Finish-reason forced to "tool_calls"
    assert results[3].choices[0].finish_reason == "tool_calls"
