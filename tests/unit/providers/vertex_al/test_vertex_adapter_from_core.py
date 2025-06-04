from app.providers.vertex_ai.adapter_from_core import convert_chat_request, convert_embedding_request

def test_vertex_message_conversion(core_chat_request, vertex_history):
    req_obj = convert_chat_request(core_chat_request)
    assert all(converted.text == fixture.text 
                for converted, fixture in zip(req_obj.contents, vertex_history))
    assert all(converted.role == fixture.role 
               for converted, fixture in zip(req_obj.contents, vertex_history))
    

def test_vertex_system_message_conversion(core_full_chat_request, vertex_full_history):
    req_obj = convert_chat_request(core_full_chat_request)
    assert all(converted.text == fixture.text 
                for converted, fixture in zip(req_obj.contents, vertex_full_history) if hasattr(converted, 'text'))
    assert all(converted.role == fixture.role 
               for converted, fixture in zip(req_obj.contents, vertex_full_history))
    

def test_vertex_config_conversion(core_full_chat_request):
    req_obj = convert_chat_request(core_full_chat_request)
    config = req_obj.generation_config
    assert config is not None
    assert config._raw_generation_config.temperature == core_full_chat_request.temperature
    assert config._raw_generation_config.top_p == core_full_chat_request.top_p
    assert config._raw_generation_config.max_output_tokens == core_full_chat_request.max_tokens
    assert config._raw_generation_config.stop_sequences == core_full_chat_request.stop


def test_embedding_request_conversion(core_embed_request, vertex_embed_request):
    converted = convert_embedding_request(core_embed_request)
    assert converted == vertex_embed_request

