# Section 7.2 - Input Validation Testing
# Based on: docs/test_design_n_planning/Testcases_7_2_Functional and Validation Testing/Test Cases_ Section 7.2 - Input Validation.md

import pytest
import httpx
from typing import Dict, Any, List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import config, logger
from fixtures.multimodal_fixtures import MultiModalFixtures


class TestInputValidation:
    """Test cases for comprehensive input validation"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_model_001(self, http_client: httpx.AsyncClient, 
                                       auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_MODEL_001: Valid model parameter validation"""
        valid_request = {
            "model": config.get_chat_model(0),
            "messages": [{"role": "user", "content": "Test message"}],
            "max_tokens": 50,
            "temperature": 0.1
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions", 
            auth_headers, valid_request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "choices" in response_data
        assert len(response_data["choices"]) > 0
        
        logger.info("FV_INP_CHAT_MODEL_001: Valid model parameter accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_model_002(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_MODEL_002: Invalid model parameter rejection"""
        invalid_request = {
            "model": "non_existent_model_123",
            "messages": [{"role": "user", "content": "Test message"}],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, invalid_request, track_cost=False
        )
        
        assert response.status_code == 422
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("FV_INP_CHAT_MODEL_002: Invalid model parameter rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_messages_001(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_MESSAGES_001: Valid messages array validation"""
        valid_request = {
            "model": config.get_chat_model(0),
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": "2+2 equals 4."},
                {"role": "user", "content": "Thank you."}
            ],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, valid_request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "choices" in response_data
        
        logger.info("FV_INP_CHAT_MESSAGES_001: Valid messages array accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_messages_002(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_MESSAGES_002: Missing messages parameter rejection"""
        invalid_request = {
            "model": config.get_chat_model(0),
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, invalid_request, track_cost=False
        )
        
        assert response.status_code == 422
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("FV_INP_CHAT_MESSAGES_002: Missing messages parameter rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_messages_003(self, http_client: httpx.AsyncClient,
                                          auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_MESSAGES_003: Empty messages array rejection"""
        invalid_request = {
            "model": config.get_chat_model(0),
            "messages": [],
            "max_tokens": 50
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, invalid_request, track_cost=False
        )
        
        assert response.status_code == 422
        
        logger.info("FV_INP_CHAT_MESSAGES_003: Empty messages array rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_temp_001(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_TEMP_001: Valid temperature parameter validation"""
        temperature_values = [0.0, 0.5, 1.0, 1.5, 2.0]
        
        for temp in temperature_values:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test message"}],
                "max_tokens": 50,
                "temperature": temp
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"Temperature {temp} should be valid"
        
        logger.info("FV_INP_CHAT_TEMP_001: Valid temperature values accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_temp_002(self, http_client: httpx.AsyncClient,
                                      auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_TEMP_002: Invalid temperature parameter rejection"""
        invalid_temperatures = [-1.0, -0.5, 2.1, 3.0, "invalid", None]
        
        for temp in invalid_temperatures:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test message"}],
                "max_tokens": 50,
                "temperature": temp
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            assert response.status_code == 422, f"Temperature {temp} should be rejected"
        
        logger.info("FV_INP_CHAT_TEMP_002: Invalid temperature values rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_tokens_001(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_TOKENS_001: Valid max_tokens parameter validation"""
        valid_token_values = [1, 10, 100, 500, 1000]
        
        for tokens in valid_token_values:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test message"}],
                "max_tokens": tokens,
                "temperature": 0.1
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            assert response.status_code == 200, f"max_tokens {tokens} should be valid"
        
        logger.info("FV_INP_CHAT_TOKENS_001: Valid max_tokens values accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_chat_tokens_002(self, http_client: httpx.AsyncClient,
                                        auth_headers: Dict[str, str], make_request):
        """FV_INP_CHAT_TOKENS_002: Invalid max_tokens parameter rejection"""
        invalid_token_values = [0, -1, -100, "invalid", None, 100000]
        
        for tokens in invalid_token_values:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test message"}],
                "max_tokens": tokens
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request, track_cost=False
            )
            
            assert response.status_code == 422, f"max_tokens {tokens} should be rejected"
        
        logger.info("FV_INP_CHAT_TOKENS_002: Invalid max_tokens values rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_file_valid_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str], 
                                       multimodal_fixtures: MultiModalFixtures,
                                       make_request):
        """FV_INP_FILE_VALID_001: Valid image file processing"""
        if not config.get_chat_model(0) in ["claude_3_5_sonnet", "claude_3_7_sonnet", "gemini-2.0-flash"]:
            pytest.skip("Multimodal testing requires vision-capable model")
        
        valid_image_message = multimodal_fixtures.get_valid_image_message(0)
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [valid_image_message],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "choices" in response_data
        
        logger.info("FV_INP_FILE_VALID_001: Valid image file processed successfully")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_file_invalid_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         multimodal_fixtures: MultiModalFixtures,
                                         make_request):
        """FV_INP_FILE_INVALID_001: Invalid image file rejection"""
        if not config.get_chat_model(0) in ["claude_3_5_sonnet", "claude_3_7_sonnet", "gemini-2.0-flash"]:
            pytest.skip("Multimodal testing requires vision-capable model")
        
        invalid_image_message = multimodal_fixtures.get_invalid_image_message(0)
        
        request = {
            "model": config.get_chat_model(0),
            "messages": [invalid_image_message],
            "max_tokens": 100
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/chat/completions",
            auth_headers, request, track_cost=False
        )
        
        assert response.status_code == 400
        response_data = response.json()
        assert "detail" in response_data
        
        logger.info("FV_INP_FILE_INVALID_001: Invalid image file rejected")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_embedding_model_001(self, http_client: httpx.AsyncClient,
                                            embedding_auth_headers: Dict[str, str],
                                            make_request):
        """FV_INP_EMBEDDING_MODEL_001: Valid embedding model validation"""
        valid_request = {
            "model": config.get_embedding_model(0),
            "input": "This is a test sentence for embedding generation."
        }
        
        response = await make_request(
            http_client, "POST", "/api/v1/embeddings",
            embedding_auth_headers, valid_request
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "data" in response_data
        assert len(response_data["data"]) > 0
        assert "embedding" in response_data["data"][0]
        
        logger.info("FV_INP_EMBEDDING_MODEL_001: Valid embedding model accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_embedding_input_001(self, http_client: httpx.AsyncClient,
                                            embedding_auth_headers: Dict[str, str],
                                            make_request):
        """FV_INP_EMBEDDING_INPUT_001: Valid input text validation"""
        test_inputs = [
            "Short text",
            "This is a longer sentence with more words for testing purposes.",
            "Special characters: !@#$%^&*()_+-=[]{}|;':\",./<>?",
            "Unicode text: 你好世界 🌍 café naïve résumé",
            "Numbers and text: The year 2024 has 365 days."
        ]
        
        for test_input in test_inputs:
            request = {
                "model": config.get_embedding_model(0),
                "input": test_input
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            assert response.status_code == 200, f"Input '{test_input[:50]}...' should be valid"
            response_data = response.json()
            assert "data" in response_data
        
        logger.info("FV_INP_EMBEDDING_INPUT_001: Various input types accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_embedding_input_002(self, http_client: httpx.AsyncClient,
                                            embedding_auth_headers: Dict[str, str],
                                            make_request):
        """FV_INP_EMBEDDING_INPUT_002: Invalid input rejection"""
        invalid_inputs = [
            "",  # Empty string
            None,  # Null value
            123,  # Numeric instead of string
            [],  # Array instead of string
            {},  # Object instead of string
            "A" * 10000  # Extremely long string
        ]
        
        for invalid_input in invalid_inputs:
            request = {
                "model": config.get_embedding_model(0),
                "input": invalid_input
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request, track_cost=False
            )
            
            assert response.status_code == 422, f"Input {type(invalid_input)} should be rejected"
        
        logger.info("FV_INP_EMBEDDING_INPUT_002: Invalid input types rejected")


class TestParameterCombinations:
    """Test parameter combinations and edge cases"""
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_combinations_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str], make_request):
        """FV_INP_COMBINATIONS_001: Valid parameter combinations"""
        combinations = [
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 50,
                "temperature": 0.0,
                "top_p": 1.0
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 100,
                "temperature": 1.0,
                "stream": False
            },
            {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 75,
                "temperature": 0.5,
                "top_p": 0.9,
                "frequency_penalty": 0.0,
                "presence_penalty": 0.0
            }
        ]
        
        for i, combo in enumerate(combinations):
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, combo
            )
            
            assert response.status_code == 200, f"Combination {i+1} should be valid"
            response_data = response.json()
            assert "choices" in response_data
        
        logger.info("FV_INP_COMBINATIONS_001: Valid parameter combinations accepted")
    
    @pytest.mark.functional
    @pytest.mark.asyncio
    async def test_fv_inp_edge_cases_001(self, http_client: httpx.AsyncClient,
                                       auth_headers: Dict[str, str], make_request):
        """FV_INP_EDGE_CASES_001: Edge case parameter values"""
        edge_cases = [
            {
                "description": "Minimum values",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "x"}],
                    "max_tokens": 1,
                    "temperature": 0.0
                }
            },
            {
                "description": "Maximum reasonable values",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test with maximum parameters"}],
                    "max_tokens": 1000,
                    "temperature": 2.0
                }
            },
            {
                "description": "Very long message content",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Long message: " + "word " * 500}],
                    "max_tokens": 50
                }
            }
        ]
        
        for case in edge_cases:
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, case["request"]
            )
            
            # Edge cases should either succeed or fail gracefully with 422
            assert response.status_code in [200, 422], f"{case['description']} should handle gracefully"
            
            if response.status_code == 200:
                response_data = response.json()
                assert "choices" in response_data
        
        logger.info("FV_INP_EDGE_CASES_001: Edge cases handled appropriately")