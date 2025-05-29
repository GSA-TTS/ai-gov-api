"""
BackendBase
~~~~~~~~~~~

This is an abstract class that represents a provider like Bedrock.
The only required field models, which should return a list of LLMModel
instances to communicate which models this backend can serve and what
capabilities they have (currently just chat and embedding).
"""

from abc import ABC, abstractmethod
from typing import Literal, AsyncGenerator
from pydantic import BaseModel
from .core.chat_schema import ChatRequest, ChatRepsonse, StreamResponse
from .core.embed_schema import EmbeddingRequest
class LLMModel(BaseModel):
    '''
    Providers will have an assortment of models they support.
    When the app starts it will look the backend's models property
    and expect a list of LLMModel objects. The id will be used in the
    API to select the model, and the capability will allow our
    code to know whether the particular model is capable of what
    we are asking.
    '''
    name: str
    id: str
    capability: Literal['chat', 'embedding']

class Backend(ABC):
    '''
    Subclasses of this represent AI service provides like Bedrock and Vertex.
    '''

    async def invoke_model(self, payload:ChatRequest) -> ChatRepsonse:
        """Handles chat completion requests. Raises NotImplementedError if not supported."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support chat completions.")

    async def embeddings(self, payload:EmbeddingRequest):
        """Handles requests for embeddings. Raises NotImplementedError if not supported."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support embeddings.")
    
    async def stream_events(self, payload: ChatRequest)  ->  AsyncGenerator[StreamResponse, None]:
        raise NotImplementedError(f"{self.__class__.__name__} does not support embeddings.")
        # make the type system know this is really an asyncgenerator
        if False: # pragma: no cover
            yield # type: ignore


    @property  
    @abstractmethod 
    def models(self) -> list[LLMModel]:
        pass

