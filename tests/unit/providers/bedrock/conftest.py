import pytest

from app.providers.bedrock.converse_schemas import (
     ConverseRequest, 
     Message, 
     ContentTextBlock,
     SystemContentBlock,
     InferenceConfig,
     ToolConfig,
     ToolInputSchema,
     ToolItem,
     ToolResultBlock,
     ToolResultBlockContent,
     ToolSpecification,
     ToolUseBlock,
     ToolUseBlockContent,
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
def bedrock_full_chat_request() -> ConverseRequest:
    # ---- tool catalogue -------------------------------------------
    tool_input_schema = ToolInputSchema(
        json = {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name"}
            },
            "required": ["location"],
        }
    )
    tool_item = ToolItem(
        tool_spec=ToolSpecification(
            name="get_weather",
            description="Get the current weather in a city",
            input_schema=tool_input_schema,
        )
    )

    # ---- messages --------------------------------------------------
    user_msg = Message(
        role="user",
        content=[ContentTextBlock(text="Hello!")]
    )

    # assistant asks to call the tool
    tool_use_msg = Message(
        role="assistant",
        content=[ToolUseBlock(
            tool_use=ToolUseBlockContent(
                tool_use_id="call_1",
                name="get_weather",
                input={"location": "Boston"},
            )
        )]
    )

    # tool replies with result (Bedrock treats tool replies as user role)
    tool_result_msg = Message(
        role="user",
        content=[ToolResultBlock(
            tool_result=ToolResultBlockContent(
                tool_use_id="call_1",
                content=[
                    ContentTextBlock(
                        text="Arrr! ’Tis 55 degrees and clear in Boston."
                    )
                ],
            )
        )]
    )

    return ConverseRequest(
        model_id="test-model",
        messages=[user_msg, tool_use_msg, tool_result_msg],
        system=[SystemContentBlock(text="Speak Pirate!")],
        inference_config=InferenceConfig(
            temperature=1.0,
            top_p=0.5,
            max_tokens=1000,
            stop_sequences=["stop", "STOP"],
        ),
        tool_config=ToolConfig(
            tools=[tool_item],
            tool_choice={"auto": {}},
        ),
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
