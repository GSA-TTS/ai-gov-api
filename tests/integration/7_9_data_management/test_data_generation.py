# Section 7.9 - Data Generation Testing
# Based on: docs/test_design_n_planning/Testcases_7_9_DataManagement/Test Cases_Data Generation.md

import pytest
import httpx
from typing import Dict, Any, List
from faker import Faker

from ..config import config, logger


class TestDataGeneration:
    """Test cases for data generation and management"""
    
    def setup_method(self):
        """Setup for data generation tests"""
        self.faker = Faker()
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_gen_prompt_diversity_001(self, http_client: httpx.AsyncClient,
                                              auth_headers: Dict[str, str],
                                              make_request):
        """TDM_GEN_PROMPT_DIVERSITY_001: Test prompt diversity"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Generate diverse prompts for testing
        diverse_prompts = [
            # Different topics
            "Explain quantum computing",
            "Write a recipe for chocolate cake",
            "Describe the history of Rome",
            "How does photosynthesis work?",
            
            # Different tones
            "Please help me understand machine learning",  # Formal
            "hey what's up with AI?",  # Informal
            "Kindly provide information about renewable energy",  # Polite
            "I need urgent help with this code bug!",  # Urgent
            
            # Different lengths
            "Hi",  # Very short
            "What is the capital of France?",  # Short
            "Can you explain the difference between supervised and unsupervised machine learning, including examples?",  # Medium
            "I'm working on a complex project that involves multiple stakeholders and I need to understand the various implications of implementing artificial intelligence solutions in a government context, including ethical considerations, technical requirements, security implications, and potential impacts on public services and citizen privacy.",  # Long
            
            # Different formats
            "List three benefits of exercise",  # List request
            "Compare cats and dogs",  # Comparison
            "What would happen if the Earth stopped rotating?",  # Hypothetical
            "Define: artificial intelligence",  # Definition
        ]
        
        successful_responses = 0
        response_lengths = []
        
        for prompt in diverse_prompts:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100,
                "temperature": 0.5
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                successful_responses += 1
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                response_lengths.append(len(content))
        
        # Verify diverse prompts are handled
        assert successful_responses >= len(diverse_prompts) * 0.8, \
            "At least 80% of diverse prompts should be processed successfully"
        
        # Verify response length diversity
        if response_lengths:
            avg_length = sum(response_lengths) / len(response_lengths)
            length_variance = sum((l - avg_length) ** 2 for l in response_lengths) / len(response_lengths)
            assert length_variance > 100, "Response lengths should show diversity"
        
        logger.info(f"TDM_GEN_PROMPT_DIVERSITY_001: {successful_responses}/{len(diverse_prompts)} prompts processed")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_gen_param_combinations_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                make_request):
        """TDM_GEN_PARAM_COMBINATIONS_001: Test parameter combinations"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Test various parameter combinations
        parameter_combinations = [
            # Low creativity, short response
            {
                "temperature": 0.1,
                "max_tokens": 50,
                "top_p": 0.9
            },
            # High creativity, medium response
            {
                "temperature": 1.5,
                "max_tokens": 150,
                "top_p": 0.95
            },
            # Balanced parameters
            {
                "temperature": 0.7,
                "max_tokens": 100,
                "top_p": 0.85
            },
            # Edge case parameters
            {
                "temperature": 0.0,
                "max_tokens": 1,
                "top_p": 1.0
            }
        ]
        
        base_prompt = "Explain artificial intelligence in simple terms"
        successful_combinations = 0
        
        for i, params in enumerate(parameter_combinations):
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": base_prompt}],
                **params
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                successful_combinations += 1
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                logger.info(f"Combination {i+1}: {len(content)} characters generated")
        
        assert successful_combinations >= len(parameter_combinations) * 0.75, \
            "At least 75% of parameter combinations should work"
        
        logger.info(f"TDM_GEN_PARAM_COMBINATIONS_001: {successful_combinations}/{len(parameter_combinations)} combinations successful")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_gen_synthetic_data_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """TDM_GEN_SYNTHETIC_DATA_001: Synthetic data generation"""
        if not config.SYNTHETIC_DATA_ENABLED:
            pytest.skip("Synthetic data generation disabled")
        
        # Generate synthetic test data using Faker
        synthetic_scenarios = []
        
        for _ in range(5):
            person = {
                "name": self.faker.name(),
                "email": self.faker.email(),
                "city": self.faker.city(),
                "job": self.faker.job()
            }
            
            prompt = f"Write a professional email from {person['name']} who works as a {person['job']} in {person['city']}"
            synthetic_scenarios.append({
                "prompt": prompt,
                "person": person
            })
        
        successful_generations = 0
        
        for scenario in synthetic_scenarios:
            request = {
                "model": config.get_chat_model(0),
                "messages": [{"role": "user", "content": scenario["prompt"]}],
                "max_tokens": 200,
                "temperature": 0.8
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            if response.status_code == 200:
                successful_generations += 1
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                
                # Verify the response relates to the synthetic data
                person_name = scenario["person"]["name"].split()[0]  # First name
                assert person_name.lower() in content.lower() or \
                       scenario["person"]["job"].lower() in content.lower(), \
                    "Response should incorporate synthetic data elements"
        
        assert successful_generations >= len(synthetic_scenarios) * 0.8, \
            "Most synthetic data scenarios should generate successfully"
        
        logger.info(f"TDM_GEN_SYNTHETIC_DATA_001: {successful_generations}/{len(synthetic_scenarios)} synthetic scenarios processed")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_gen_embedding_diversity_001(self, http_client: httpx.AsyncClient,
                                                 embedding_auth_headers: Dict[str, str],
                                                 make_request):
        """TDM_GEN_EMBEDDING_DIVERSITY_001: Embedding input diversity"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Generate diverse embedding inputs
        diverse_inputs = [
            # Technical content
            "Machine learning algorithms analyze patterns in data",
            
            # Natural language
            "The beautiful sunset painted the sky in vibrant colors",
            
            # Factual information
            "Paris is the capital city of France with a population of 2.1 million",
            
            # Abstract concepts
            "Freedom represents the ability to make choices without constraint",
            
            # Numerical content
            "The equation E=mc² describes the relationship between mass and energy",
            
            # Mixed content
            "In 2024, artificial intelligence technologies continued to advance rapidly"
        ]
        
        embeddings_generated = 0
        embedding_dimensions = []
        
        for input_text in diverse_inputs:
            request = {
                "model": config.get_embedding_model(0),
                "input": input_text
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/embeddings",
                embedding_auth_headers, request
            )
            
            if response.status_code == 200:
                embeddings_generated += 1
                response_data = response.json()
                embedding = response_data["data"][0]["embedding"]
                embedding_dimensions.append(len(embedding))
        
        # Verify embeddings are generated for diverse inputs
        assert embeddings_generated >= len(diverse_inputs) * 0.8, \
            "Most diverse inputs should generate embeddings"
        
        # Verify consistent embedding dimensions
        if embedding_dimensions:
            assert all(dim == embedding_dimensions[0] for dim in embedding_dimensions), \
                "All embeddings should have consistent dimensions"
        
        logger.info(f"TDM_GEN_EMBEDDING_DIVERSITY_001: {embeddings_generated}/{len(diverse_inputs)} embeddings generated")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_gen_stress_data_001(self, http_client: httpx.AsyncClient,
                                         auth_headers: Dict[str, str],
                                         make_request):
        """TDM_GEN_STRESS_DATA_001: Stress testing with generated data"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Generate stress test scenarios
        stress_scenarios = [
            # Rapid short requests
            {"count": 5, "content": "Hi", "max_tokens": 10},
            
            # Medium complexity requests
            {"count": 3, "content": "Explain the concept of neural networks", "max_tokens": 100},
            
            # Resource intensive requests
            {"count": 2, "content": "Write a detailed essay about climate change", "max_tokens": 500}
        ]
        
        total_requests = 0
        successful_requests = 0
        
        for scenario in stress_scenarios:
            for i in range(scenario["count"]):
                request = {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": scenario["content"]}],
                    "max_tokens": scenario["max_tokens"],
                    "temperature": 0.5
                }
                
                total_requests += 1
                
                response = await make_request(
                    http_client, "POST", "/api/v1/chat/completions",
                    auth_headers, request
                )
                
                if response.status_code == 200:
                    successful_requests += 1
                
                # Small delay between requests
                import asyncio
                await asyncio.sleep(0.1)
        
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        
        # Should handle most stress test requests
        assert success_rate >= 0.7, f"Success rate {success_rate:.2%} should be at least 70%"
        
        logger.info(f"TDM_GEN_STRESS_DATA_001: {successful_requests}/{total_requests} stress test requests successful")


class TestDataParameterization:
    """Test data parameterization strategies"""
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_model_matrix_001(self, http_client: httpx.AsyncClient,
                                            auth_headers: Dict[str, str],
                                            make_request):
        """TDM_PARAM_MODEL_MATRIX_001: Model parameter matrix testing"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Test across available models
        test_prompt = "What is machine learning?"
        model_results = []
        
        for model in config.CHAT_MODELS:
            request = {
                "model": model,
                "messages": [{"role": "user", "content": test_prompt}],
                "max_tokens": 100,
                "temperature": 0.5
            }
            
            response = await make_request(
                http_client, "POST", "/api/v1/chat/completions",
                auth_headers, request
            )
            
            result = {
                "model": model,
                "status": response.status_code,
                "success": response.status_code == 200
            }
            
            if response.status_code == 200:
                response_data = response.json()
                result["response_length"] = len(response_data["choices"][0]["message"]["content"])
            
            model_results.append(result)
        
        # At least some models should work
        successful_models = [r for r in model_results if r["success"]]
        assert len(successful_models) >= 1, "At least one model should work"
        
        logger.info(f"TDM_PARAM_MODEL_MATRIX_001: {len(successful_models)}/{len(config.CHAT_MODELS)} models successful")
    
    @pytest.mark.data_management
    @pytest.mark.asyncio
    async def test_tdm_param_scope_validation_001(self, http_client: httpx.AsyncClient,
                                                auth_headers: Dict[str, str],
                                                embedding_auth_headers: Dict[str, str],
                                                make_request):
        """TDM_PARAM_SCOPE_VALIDATION_001: API key scope parameterization"""
        if not config.ENABLE_DATA_GENERATION_TESTS:
            pytest.skip("Data generation tests disabled")
        
        # Test different scopes with appropriate endpoints
        scope_tests = [
            {
                "description": "Chat scope with chat endpoint",
                "headers": auth_headers,
                "endpoint": "/api/v1/chat/completions",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test chat scope"}],
                    "max_tokens": 50
                },
                "expected_success": True
            },
            {
                "description": "Embedding scope with embedding endpoint",
                "headers": embedding_auth_headers,
                "endpoint": "/api/v1/embeddings",
                "request": {
                    "model": config.get_embedding_model(0),
                    "input": "Test embedding scope"
                },
                "expected_success": True
            },
            {
                "description": "Embedding scope with chat endpoint",
                "headers": embedding_auth_headers,
                "endpoint": "/api/v1/chat/completions",
                "request": {
                    "model": config.get_chat_model(0),
                    "messages": [{"role": "user", "content": "Test wrong scope"}],
                    "max_tokens": 50
                },
                "expected_success": False
            }
        ]
        
        for test in scope_tests:
            response = await make_request(
                http_client, "POST" if test["endpoint"] != "/api/v1/models" else "GET",
                test["endpoint"], test["headers"], test["request"],
                track_cost=test["expected_success"]
            )
            
            if test["expected_success"]:
                assert response.status_code == 200, \
                    f"{test['description']} should succeed"
            else:
                assert response.status_code == 401, \
                    f"{test['description']} should fail with 401"
        
        logger.info("TDM_PARAM_SCOPE_VALIDATION_001: Scope parameterization validated")