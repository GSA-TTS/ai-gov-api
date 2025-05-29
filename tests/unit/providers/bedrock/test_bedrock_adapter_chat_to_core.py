from datetime import datetime
from unittest import mock
from app.providers.bedrock.adapter_to_core import bedrock_chat_response_to_core

@mock.patch("app.providers.bedrock.adapter_to_core.datetime")
def test_bedrock_chat_response_to_core(mock_datetime, bedrock_chat_response, core_chat_reponse):
    # bedrock does not return a created date, so use the current time when converting
    mock_datetime.now.return_value = datetime(2024, 12, 25)

    converted = bedrock_chat_response_to_core(bedrock_chat_response, model="test-model")
    assert converted == core_chat_reponse