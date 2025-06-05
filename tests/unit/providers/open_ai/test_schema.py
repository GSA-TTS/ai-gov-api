from app.providers.open_ai.schemas import ChatCompletionRequest, ChatCompletionResponse

def test_initial_request_with_tools():
    """It should parse OpenAI requests with no validation errors"""
    request = {
        "model": "gpt-4.1",
        "messages": [
            {"role": "user", "content": "What is the weather like in Boston today?"}
        ],
        "tools": [
            {
                "type": "function",
                "description": "Get the current weather in a given location",
                "function": {
                    "name": "get_current_weather",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {
                                "type": "string",
                                "description": "The city and state, e.g. San Francisco, CA",
                            },
                            "unit": {
                                "type": "string",
                                "enum": ["celsius", "fahrenheit"],
                            },
                        },
                        "required": ["location"],
                    },
                },
            }
        ],
        "tool_choice": "auto",
    }

    model = ChatCompletionRequest.model_validate(request)
    result = model.model_dump(by_alias=True, exclude_none=True)

    # model_id is not in the bedrock spec, we use it internally
    # it should not get serialized when sending to bedrock
    assert "model_id" not in result
    assert result["messages"] == request["messages"]

def test_model_tool_response():
    """It should parse OpenAI responses with no validation errors"""

    output = {
        "object": "chat.completion",
        "created": 1699896916,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "type": "function",
                            "function": {
                                "name": "get_current_weather",
                                "arguments": '{\n"location": "Boston, MA"\n}',
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {
            "prompt_tokens": 82,
            "completion_tokens": 17,
            "total_tokens": 99
        },
    }

    model = ChatCompletionResponse.model_validate(output)
    result = model.model_dump(by_alias=True, exclude_none=True)
    assert result == output