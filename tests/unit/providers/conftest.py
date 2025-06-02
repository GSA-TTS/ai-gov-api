from datetime import datetime
import pytest
from app.providers.core.chat_schema import (
    ChatRequest,
    UserMessage,
    SystemMessage,
    AssistantMessage,
    TextPart,
    ChatRepsonse,
    Response,
    CompletionUsage,
    ToolCall,
    ToolDefinition,
    FunctionObject,
    ToolMessage,
    FunctionParameters,
    FunctionCall
)
from app.providers.core.embed_schema import EmbeddingRequest, EmbeddingResponse, EmbeddingData, EmbeddingUsage

@pytest.fixture
def core_chat_request():
    return ChatRequest(
        model="test-model",
        messages = [
            UserMessage(content=[TextPart(text="Hello!")]),
            AssistantMessage(content=[TextPart(text="Hello! How can I assist you?")])
        ]
    )

@pytest.fixture
def core_full_chat_request() -> ChatRequest:
    weather_params = FunctionParameters(
        properties={
            "location": {"type": "string", "description": "City name"}
        },
        required=["location"]
    )
    weather_def = ToolDefinition(
        function=FunctionObject(
            name="get_weather",
            description="Get the current weather in a city",
            parameters=weather_params,
        )
    )

    return ChatRequest(
        model="test-model",
        temperature=1.0,
        top_p=.5,
        max_tokens=1000,
        stream=True,
        stop=["stop", "STOP"],
        tools=[weather_def],
        tool_choice="auto",
        messages=[
            SystemMessage(content=[TextPart(text="Speak Pirate!")]),
            UserMessage(content=[TextPart(text="Hello!")]),
            # assistant requests the tool
            AssistantMessage(
                content=[],
                tool_calls=[
                    ToolCall(
                        id="call_1",
                        function=FunctionCall(
                            name="get_weather",
                            arguments='{"location":"Boston"}'
                        )
                    )
                ],
            ),
            # tool replies
            ToolMessage(
                tool_call_id="call_1",
                content=[TextPart(type='text', text='Arrr! ’Tis 55 degrees and clear in Boston.')],
            ),
        ],
    )



@pytest.fixture
def core_chat_reponse():
    return ChatRepsonse(
        model="test-model",
        created=datetime(2024, 12, 25),
        choices=[
            Response(content="It was the afternoon of my eighty-first birthday, and I was in bed…")
        ],
        usage=CompletionUsage(prompt_tokens=10, completion_tokens=12, total_tokens=22)
    )


@pytest.fixture
def core_embed_request():
    return EmbeddingRequest(
        input = ["this is a test", "something else"],
        model = "test_model",
        encoding_format="float",
        input_type = 'search_document'
    )

@pytest.fixture
def core_embed_response():
    return EmbeddingResponse(
        model="test-model",
        data = [
            EmbeddingData(index=0, embedding=[-0.1, 0.2, -0.5]),
            EmbeddingData(index=1, embedding=[0.4, 0.2, 0.5])
        ],
        usage=EmbeddingUsage(
            prompt_tokens=12,
            total_tokens=12
        )
    )