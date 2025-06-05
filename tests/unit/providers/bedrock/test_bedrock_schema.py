from app.providers.bedrock.converse_schemas import ConverseRequest, ConverseResponse


def test_inital_tool_request():
    '''It should parse Bedrock requests with no validation errors'''
    request = {
        "model_id": "test_model",
        "messages": [
            {
            "role": "user",
            "content": [
                { "text": "What is the most popular song on WZPZ?" }
            ]
            }
        ],
        "toolConfig": {
            "tools": [
            {
                "toolSpec": {
                "name": "top_song",
                "description": "Get the most popular song played on a radio station.",
                "inputSchema": {
                    "json": {
                    "type": "object",
                    "properties": {
                        "sign": {
                        "type": "string",
                        "description": "The station call-sign, e.g. WZPZ or WKRP."
                        }
                    },
                    "required": ["sign"]
                    }
                }
                }
            }
            ],
            "toolChoice": { "tool": { "name": "top_song" }}    
        }
    }
    model = ConverseRequest.model_validate(request)
    result = model.model_dump(by_alias=True, exclude_none=True) 

    # model_id is not in the bedrock spec, we use it internally
    # it should not get serialized when sending to bedrock
    assert 'model_id' not in result
    assert result['messages'] == request['messages']
    assert result['toolConfig'] == request['toolConfig']


def test_model_tool_response():

    output = {
        "output": {
            "message": {
            "role": "assistant",
            "content": [
                {
                "toolUse": {
                    "toolUseId": "tooluse_kZJMlvQmRJ6eAyJE5GIl7Q",
                    "name":       "top_song",
                    "input": { "sign": "WZPZ" }
                }
                }
            ]
            }
        },
        "stopReason": "tool_use",
        "usage": {
            "inputTokens": 14,
            "outputTokens": 23,
            "totalTokens": 37
        }
    }
    model = ConverseResponse.model_validate(output)
    # make sure round trip works
    result = model.model_dump(by_alias=True) 
    assert result == output

def test_followup_request():
    request ={
        "model_id": "some model",
        "messages": [
            {
            "role": "user",
            "content": [
                {
                "toolResult": {
                    "toolUseId": "tooluse_kZJMlvQmRJ6eAyJE5GIl7Q",
                    "content": [
                    {
                        "json": {
                        "song":   "Elemental Hotel",
                        "artist": "8 Storey Hike"
                        }
                    }
                    ]
                }
                }
            ]
            }
        ]
    }
    model = ConverseRequest.model_validate(request)
    result = model.model_dump(by_alias=True, exclude_none=True) 
    assert 'model_id' not in result
    assert result['messages'] == request['messages']
