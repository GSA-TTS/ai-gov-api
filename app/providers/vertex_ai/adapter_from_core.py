import json
from functools import singledispatch
from typing import List, Dict, Optional, Any
import structlog

from vertexai.language_models import TextEmbeddingInput
from vertexai.generative_models import (
    Part,
    Content,
    GenerationConfig,
    FunctionCall,
    Tool,
    FunctionDeclaration,
    ToolConfig
)
from ..core.chat_schema import (
    SystemMessage,
    TextPart,
    UserMessage,
    AssistantMessage,
    ImagePart,
    FilePart,
    ToolMessage,
)
from ..core.embed_schema import EmbeddingRequest as CoreEmbedRequest
from ..core.chat_schema import ChatRequest
from .schemas import EmbeddingRequest, VertexGenerateRequest

logger = structlog.get_logger()

@singledispatch
def _part_to_vtx(part) -> Part:
    raise TypeError(f"No converter for {type(part)}")

@_part_to_vtx.register
def _(part: TextPart) -> Part:
    return Part.from_text(part.text)

@_part_to_vtx.register
def _(part: ImagePart) -> Part:
    return Part.from_data(data=part.bytes_, mime_type=f"image/{part.file_type}")

@_part_to_vtx.register
def _(part: FilePart) -> Part:
    return Part.from_data(data=part.bytes_, mime_type="application/pdf")
    

def convert_chat_request(req: ChatRequest) -> VertexGenerateRequest:
    vertex_contents: List[Content] = []
    tool_id_to_func_name_map: Dict[str, str] = {}

    for core_msg in req.messages:
        current_parts: List[Part] = []
        current_role: Optional[str] = None

        if isinstance(core_msg, SystemMessage):
            # vertex doesn't have system messages they recommend using user/assistant pairs
            system_message = '\n'.join(content.text for content in core_msg.content)
            vertex_contents.append(Content(role="user", parts=[Part.from_text(system_message)]))
            vertex_contents.append(Content(role="model", parts=[Part.from_text("Okay, I will follow these instructions.")]))
            continue

        elif isinstance(core_msg, UserMessage):
            current_role = "user"
            for part_data in core_msg.content:
                current_parts.append(_part_to_vtx(part_data))
                
        elif isinstance(core_msg, AssistantMessage):
            current_role = "model"
            # Handle textual/image content from assistant
            if core_msg.content:
                for part_data in core_msg.content:
                    current_parts.append(_part_to_vtx(part_data))

            # Handle tool calls made by the assistant
            if core_msg.tool_calls:
                for tool_call in core_msg.tool_calls:
                    if tool_call.type == "function":
                        # Store mapping for potential ToolMessage follow-up
                        tool_id_to_func_name_map[tool_call.id] = tool_call.function.name
                        try:
                            args_dict = json.loads(tool_call.function.arguments)
                        except json.JSONDecodeError as e:
                            # Handle malformed JSON arguments; here, we log and use empty dict
                            logger.warning(f"Warning: Could not parse JSON arguments for tool call {tool_call.id} "
                                  f"(function: {tool_call.function.name}). Error: {e}. Using empty arguments.")
                            args_dict = {}
                        
                        # Create Part with FunctionCall —
                        # For somereason Part.from_function_call is not in the SDK
                        # and Part(function_call=function_call) does not work
                        # so this is kind of a hack
                        function_call = FunctionCall(
                            name=tool_call.function.name,
                            args=args_dict
                        )                      
                        current_parts.append( Part.from_dict({'function_call': function_call.to_dict()}))
                            
        
        elif isinstance(core_msg, ToolMessage):
            # This is a response from a tool execution
            # Vertex API uses role "function" for content containing function responses
            current_role = "function"
            function_name = tool_id_to_func_name_map.get(core_msg.tool_call_id)
            
            if not function_name:
                raise ValueError(
                    f"ToolMessage with tool_call_id '{core_msg.tool_call_id}' references an unknown "
                    f"or out-of-order tool call. Ensure AssistantMessage with the call precedes this."
                )

            tool_response_content_str = ""
            if isinstance(core_msg.content, str):
                tool_response_content_str = core_msg.content
            elif core_msg.content:  # Sequence[TextPart]
                tool_response_content_str = "".join(
                    tp.text for tp in core_msg.content if isinstance(tp, TextPart)
                )
            
            # Use Part.from_function_response() method
            current_parts.append(Part.from_function_response(
                name=function_name,
                response={"content": tool_response_content_str}
            ))
        
        # Add the constructed Content object if it has a role and parts
        if current_role and current_parts:
            vertex_contents.append(Content(role=current_role, parts=current_parts))
        elif current_role and not current_parts:
            logger.warning(f"Warning: Message of role '{current_role}' resulted in no parts and was skipped.")

    # Convert `req.tools` (ToolDefinition) to Vertex `Tool` objects
    vertex_tools: Optional[List[Tool]] = None
    if req.tools:
        vertex_tools = []
        for tool_def in req.tools:
            if tool_def.type == "function":
                # Updated: Create parameters dict directly without Schema.from_dict
                params_dict = {
                    "type": tool_def.function.parameters.type,  # Should be "object"
                    "properties": tool_def.function.parameters.properties,
                }
                if tool_def.function.parameters.required is not None:
                    params_dict["required"] = tool_def.function.parameters.required
                
                func_decl = FunctionDeclaration(
                    name=tool_def.function.name,
                    description=tool_def.function.description or "",
                    parameters=params_dict  # Pass dict directly
                )
                vertex_tools.append(Tool(function_declarations=[func_decl]))

    # Convert `req.tool_choice` to Vertex `ToolConfig`
    vertex_tool_config: Optional[ToolConfig] = None
    if req.tool_choice:
        mode: Optional[ToolConfig.FunctionCallingConfig.Mode] = None
        allowed_function_names: Optional[List[str]] = None

        if isinstance(req.tool_choice, str):
            if req.tool_choice == "none":
                mode = ToolConfig.FunctionCallingConfig.Mode.NONE
            elif req.tool_choice == "auto":
                mode = ToolConfig.FunctionCallingConfig.Mode.AUTO
            elif req.tool_choice == "required": 
                if not vertex_tools:  # "required" needs tools to choose from
                    raise ValueError("'tool_choice': 'required' was specified, but no tools were provided.")
                mode = ToolConfig.FunctionCallingConfig.Mode.ANY  # Force a call from any available tool
            else:  # Assumed to be a specific function name
                mode = ToolConfig.FunctionCallingConfig.Mode.ANY  # Force this specific function
                allowed_function_names = [req.tool_choice]
        
        elif isinstance(req.tool_choice, dict):  # e.g., {"type": "function", "function": {"name": "my_func"}}
            if req.tool_choice.get("type") == "function":
                func_spec = req.tool_choice.get("function")
                if func_spec and isinstance(func_spec, dict) and "name" in func_spec:
                    mode = ToolConfig.FunctionCallingConfig.Mode.ANY  # Force this specific function
                    allowed_function_names = [func_spec["name"]]
                else:
                    raise ValueError(f"Invalid tool_choice dictionary format: {req.tool_choice}")
            else:
                raise ValueError(f"Unsupported tool_choice type in dictionary: {req.tool_choice.get('type')}")
        
        if mode is not None:
            fcc_kwargs: Dict[str, Any] = {"mode": mode}
            if allowed_function_names:
                fcc_kwargs["allowed_function_names"] = allowed_function_names
            vertex_tool_config = ToolConfig(function_calling_config=ToolConfig.FunctionCallingConfig(**fcc_kwargs))

    elif vertex_tools:  # Tools are provided, but no specific tool_choice => default to AUTO
        vertex_tool_config = ToolConfig(
            function_calling_config=ToolConfig.FunctionCallingConfig(mode=ToolConfig.FunctionCallingConfig.Mode.AUTO)
        )

    gen_config_params = {}
    if req.temperature is not None:
        gen_config_params["temperature"] = req.temperature
    if req.max_tokens is not None:
        gen_config_params["max_output_tokens"] = req.max_tokens
    if req.top_p is not None:
        gen_config_params["top_p"] = req.top_p
    if req.stop:  # If req.stop is an empty list, it might be passed as is.
        gen_config_params["stop_sequences"] = req.stop
    
    vertex_generation_config = GenerationConfig(**gen_config_params) if gen_config_params else None

    return VertexGenerateRequest(
        contents=vertex_contents,
        stream=req.stream,
        generation_config=vertex_generation_config,
        tools=vertex_tools,
        tool_config=vertex_tool_config,
    )

def convert_embedding_request(req: CoreEmbedRequest) -> EmbeddingRequest:

    type_map = {
        "search_document": "RETRIEVAL_DOCUMENT",
        "search_query": "RETRIEVAL_QUERY",
        "classification": "CLASSIFICATION",
        "clustering": "CLUSTERING",
        "semantic_similarity": "SEMANTIC_SIMILARITY",
    }

    input_type = type_map.get(req.input_type) if req.input_type is not None else None

    return EmbeddingRequest(
        auto_truncate =True,
        output_dimensionality=req.dimensions,
        texts = [
            TextEmbeddingInput(text=text, task_type=input_type) 
            for text in req.input
        ]
    )

    
    