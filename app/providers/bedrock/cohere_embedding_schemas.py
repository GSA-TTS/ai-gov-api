'''
Types for representing Bedrocks cohere api. 
https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-embed.html

These are the source and destination for conversions to and from 
the OpenAI embedding API format.
'''

from typing import List, Literal, Any, get_args, Optional, Dict
from pydantic import BaseModel, Field, field_validator


class CohereRequest(BaseModel):
    model: str = Field(..., exclude=True)
    texts: List[str] = Field(..., min_length=0, max_length=96)
    input_type: Literal["search_document", "search_query", "classification", "clustering"]
    truncate: Literal["NONE", "START", "END"] = "NONE"
    embedding_types: List[Literal["float", "int8", "uint8", "binary", "ubinary"]] = ["float"]
   
    @field_validator('input_type', mode='before')
    @classmethod 
    def validate_and_coerce_input_type(cls, v: Any) -> str:
        """
        Cohere only supports a subset of values our API will support. 
        This allows use to just use a default when something else is passed in.
        """
        allowed_values = get_args(cls.model_fields['input_type'].annotation)
        default_value = "search_document"

        if v in allowed_values:
            return v 
        else:
            return default_value 


class CohereImageDscription(BaseModel):
    width: int
    height: int
    format: str
    bit_depth: int

class CohereRepsonse(BaseModel):
    embeddings: Dict[str, List[List[float]]]
    id: str
    response_type: str
    texts: List[str]
    images: Optional[List[CohereImageDscription]] = None
