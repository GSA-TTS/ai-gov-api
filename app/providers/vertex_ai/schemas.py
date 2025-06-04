# Google Vertex provides typed python objects
# which we can use until it introduces issues

from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from vertexai.language_models import TextEmbeddingInput
from vertexai.generative_models import GenerationConfig, Content, SafetySetting, Tool, ToolConfig


class VertexGenerateRequest(BaseModel):
    # setting this config to allow the direct use of vertex types 
    model_config = ConfigDict(arbitrary_types_allowed=True)
    contents: List[Content]
    generation_config: GenerationConfig | None = None
    safety_settings: SafetySetting | None = None
    stream: Optional[bool] = False
    tools: List[Tool] | None
    tool_config: ToolConfig | None

class EmbeddingRequest(BaseModel):
    texts: List[str | TextEmbeddingInput]
    auto_truncate: bool = True
    output_dimensionality: Optional[int] = None
