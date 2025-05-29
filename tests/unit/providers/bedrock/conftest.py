import pytest

from app.providers.bedrock.converse_schemas import (
     ConverseRequest, 
     Message, 
     ContentTextBlock,
     SystemContentBlock,
     InferenceConfig,
     ConverseResponse,
     ConverseResponseOutput,
     ConverseResponseUsage
)

@pytest.fixture(scope="module") 
def bedrock_chat_request():
    return ConverseRequest(
        model_id= "test-model",
        messages = [
            Message(role="user", content=[ContentTextBlock(text="Hello!")]),
            Message(role="assistant", content=[ContentTextBlock(text="Hello! How can I assist you?")])
        ]
    )

@pytest.fixture
def bedrock_full_chat_request():
    return ConverseRequest(
        model_id= "test-model",
        messages = [
            Message(role="user", content=[ContentTextBlock(text="Hello!")]),
            Message(role="assistant", content=[ContentTextBlock(text="Hello! How can I assist you?")])
        ],
        system=[
            SystemContentBlock(text="Speak Pirate!")
        ],
        inference_config=InferenceConfig(
            temperature=1.0,
            top_p=.5,
            max_tokens=1000,
            stop_sequences=["stop", "STOP"]
        )
    )


@pytest.fixture
def bedrock_chat_response():
    return ConverseResponse(
        output={"message": ConverseResponseOutput(
            role="assistant",
            content=[
                ContentTextBlock(text='It was the afternoon of my eighty-first birthday, and I was in bed…')
            ]
        )},
        usage=ConverseResponseUsage(
            input_tokens=10,
            output_tokens=12,
            total_tokens=22
        )
    )
