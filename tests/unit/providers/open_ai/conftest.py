import pytest
from datetime import datetime

from app.providers.open_ai.schemas import (
    ChatCompletionRequest,
    UserMessage,
    SystemMessage,
    AssistantMessage,
    TextContentPart,
    ChatCompletionResponse,
    ChatCompletionChoice,
    ChatCompletionResponseMessage,
    ChatCompletionUsage,
    ImageContentPart,
    ImageUrl, 
    FileContentPart,
    FileContent,
    FunctionParameters,
    FunctionObject,
    FunctionCall,
    ToolDefinition,
    ToolCall,
    ToolMessage

)

@pytest.fixture
def openai_chat_request():
    return ChatCompletionRequest(
        model="test-model",
        messages = [
            UserMessage(content=[TextContentPart(text="Hello!")]),
            AssistantMessage(content=[TextContentPart(text="Hello! How can I assist you?")])
        ]
    )

@pytest.fixture
def openai_full_chat_request() -> ChatCompletionRequest:
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

    return ChatCompletionRequest(
        model="test-model",
        temperature=1.0,
        top_p=.5,
        max_tokens=1000,
        stream=True,
        stop=["stop", "STOP"],
        tools=[weather_def],                 # NEW  ←───────────────
        tool_choice="auto",                  # optional
        messages=[
            # NB: use *OpenAI* message types here
            SystemMessage(content=[TextContentPart(text="Speak Pirate!")]),
            UserMessage(content=[TextContentPart(text="Hello!")]),
            AssistantMessage(
                content=None,                # spec says null when only tool calls
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
            ToolMessage(
                tool_call_id="call_1",
                content=[TextContentPart(text="Arrr! ’Tis 55 degrees and clear in Boston.")]
            ),
        ],
    )
@pytest.fixture
def openai_chat_reponse():
    return ChatCompletionResponse(
        model="test-model",
        created=datetime(2024, 12, 25),
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatCompletionResponseMessage(
                    content='It was the afternoon of my eighty-first birthday, and I was in bed…'
                    )
            )
        ],
        usage=ChatCompletionUsage(prompt_tokens=10, completion_tokens=12, total_tokens=22)
    )


@pytest.fixture(scope="module") 
def open_ai_example_image(request):
    return ChatCompletionRequest(
        model="test-model",
        messages=[
            UserMessage(role="user", content=[
                ImageContentPart(image_url=ImageUrl(url=request.param, detail="auto"))
            ])
        ]
    )

@pytest.fixture(scope="module") 
def open_ai_example_file(request):
    return ChatCompletionRequest(
        model="test-model",
        messages=[
            UserMessage(role="user", content=[
                FileContentPart(file=FileContent(file_data=request.param))
            ])
        ],
        temperature=0,
        max_tokens=300
    )