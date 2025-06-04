import pytest
 
from fastapi.testclient import TestClient
from app.auth.dependencies import valid_api_key
from app.auth.schemas import Scope
from app.main import app
from app.routers.api_v1 import chat_backend
from app.auth.models import APIKey
from app.providers.exceptions import BedrockValidationError, BedrockThrottled, BedrockNotFound

API_KEY_REPOSITORY_PATH = "app.auth.dependencies.APIKeyRepository" 


@pytest.fixture()
def fake_bedrock(request):
    class FakeBedrock:
        async def invoke_model(self, payload):
            # The param will be an exception 
            raise request.param

        async def stream_events(self, payload):
            if False:                       
                yield None
    return FakeBedrock()

@pytest.fixture()
def client(fake_bedrock):
    def fake_valid_api_key():
        return APIKey(
            id=0,
            key_prefix="test",
            scopes=[Scope.MODELS_INFERENCE],  
            is_active=True,
            expires_at=None,
        )

    app.dependency_overrides[valid_api_key] = fake_valid_api_key
    app.dependency_overrides[chat_backend] = lambda: fake_bedrock

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()

@pytest.mark.parametrize('fake_bedrock, status_code, json_res', [
        [BedrockValidationError("location is missing"), 400, {"detail": "location is missing"}],
        [BedrockThrottled("Too many requets"), 429, {"detail": "Too many requets"}],
        [BedrockNotFound("Model not found"), 404, {"detail": "Model not found"}],
    ], indirect=['fake_bedrock'])
def test_bedrock_errors(client, status_code, json_res):
    payload = {
        "model": "claude_3_haiku",
        "messages": [],
        "stream": False
    }

    response = client.post("api/v1/chat/completions", json=payload)
    assert response.status_code == status_code
    assert response.json() == json_res