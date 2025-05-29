import pytest

import app.providers.core.chat_schema as core
from app.providers.bedrock.adapter_to_core import bedrock_chat_stream_response_to_core


async def fake_bedrock_stream(events):
    '''Mimick Bedrock Stream for a single event'''
    for event in events:
        yield event

@pytest.mark.asyncio
async def test_message_start_event_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "messageStart": {"role": "assistant"}
    }])

    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    converted = chunks[0]
    assert isinstance(converted, core.StreamResponse)
    assert converted.choices[0].delta is not None
    assert converted.choices[0].delta.role == "assistant"
    assert converted.choices[0].delta.content == ""
    assert converted.model == "some_model"

@pytest.mark.asyncio
async def test_content_block_start_event_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "contentBlockStart": { 
            "contentBlockIndex": 3,
            "start": {"text": {}}
        }
    }])
    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    assert len(chunks) == 0    

@pytest.mark.asyncio
async def test_content_block_delta_event_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "contentBlockDelta": { 
            "contentBlockIndex": 2,
            "delta": { "text": "Hello"}
        }
    }])

    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    converted = chunks[0]
    assert isinstance(converted, core.StreamResponse)
    assert converted.choices[0].delta is not None
    assert converted.choices[0].delta.content == "Hello"

@pytest.mark.asyncio
async def test_content_block_stop_event_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "contentBlockStop": { "contentBlockIndex": 10}
    }])
    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    assert len(chunks) == 0 

@pytest.mark.asyncio
async def test_message_stop_event_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "messageStop": { 
            "additionalModelResponseFields": {},
            "stopReason": "end_message"
        },
    }])
    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    converted = chunks[0]
    assert isinstance(converted, core.StreamResponse)
    assert converted.choices[0].delta is not None
    assert converted.choices[0].finish_reason == "end_message"


@pytest.mark.asyncio
async def test_metadata_conversion():
    bedrock_chunk = fake_bedrock_stream([{
        "metadata": { 
            "metrics": { 
                "latencyMs": 762
            },
            "usage": { 
                "inputTokens": 20,
                "outputTokens": 23,
                "totalTokens": 43
            }   
        }
    }])
    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    converted = chunks[0]
    assert len(converted.choices) == 0
    assert isinstance(converted, core.StreamResponse)
    assert converted.usage is not None
    assert converted.usage.prompt_tokens == 20
    assert converted.usage.completion_tokens == 23
    assert converted.usage.total_tokens == 43


@pytest.mark.asyncio
async def test_usage_comes_last():
    '''Even when usage is not last in a bedrock stream it should be yielded at the end'''
    bedrock_chunk = fake_bedrock_stream([
        {
            "metadata": { 
                "metrics": { 
                    "latencyMs": 762
                },
                "usage": { 
                    "inputTokens": 20,
                    "outputTokens": 23,
                    "totalTokens": 43
                }   
            }
        },
        {
        "messageStart": {"role": "assistant"}
        },
        {
            "messageStop": { 
                "additionalModelResponseFields": {},
                "stopReason": "end_message"
            }
        }
    ])
    chunks = [
        chunk
        async for chunk in bedrock_chat_stream_response_to_core(
            bedrock_chunk, id="abc", model='some_model'
        )
    ]
    assert len(chunks) == 3
    assert chunks[-1].usage is not None

