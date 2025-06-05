import json
from functools import singledispatch
from typing import List, Dict, Optional, Any, Sequence, cast
import structlog
from itertools import groupby

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
    ToolDefinition,
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
    
def handle_assistant_messages(
        messages_in_group:List[AssistantMessage], 
        tool_id_to_func_name_map: Dict[str, str]
    ) -> List[Content]:
    '''
    Handles converting assistant responses. These may contain 0 or more tool calls.
    '''
    vertex_contents: List[Content] = []
    for core_msg in messages_in_group:
        assistant_parts: List[Part] = []
        if core_msg.content: # Text/image content
            for part_data in core_msg.content:
                assistant_parts.append(_part_to_vtx(part_data))
        
        if core_msg.tool_calls:
            # Core ToolCall -> Vertex FunctionCall
            for tool_call in core_msg.tool_calls:
                if tool_call.function.name and tool_call.id:
                    tool_id_to_func_name_map[tool_call.id] = tool_call.function.name
                try:
                    args_dict = json.loads(tool_call.function.arguments or '{}') 
                except json.JSONDecodeError as e:
                    logger.warning(f"Malformed JSON for tool {tool_call.id} ({tool_call.function.name}): {e}. Using empty args.")
                    args_dict = {}
                
                fc = FunctionCall(
                    name=tool_call.function.name or "unknown", 
                    args=args_dict
                )
                assistant_parts.append(Part.from_dict({'function_call': fc.to_dict()}))
        if assistant_parts:
            vertex_contents.append(Content(role="model", parts=assistant_parts))
    return vertex_contents   

def handle_tool_messages(
        messages_in_group:List[ToolMessage],
        tool_id_to_func_name_map: Dict[str, str]
    ) -> Content | None:
    '''
    Handles tool messages (result of calling tools)
    Unlile OpenAI, Vertex needs these grouped together 
    in a single content object if there are more than one.
    '''
    tool_response_collection_parts: List[Part] = []
    vertex_content: Content | None = None

    for core_msg in messages_in_group:
        function_name = tool_id_to_func_name_map.get(core_msg.tool_call_id)
        if not function_name:
            logger.error(f"ToolMessage {core_msg.tool_call_id} has no matching call ID mapped. Skipping.")
            continue # raise exception?

        tool_response_content_str = ""
        if isinstance(core_msg.content, str):
            tool_response_content_str = core_msg.content
        elif core_msg.content: # Assuming Sequence[TextPart]
            tool_response_content_str = "".join(
                tp.text for tp in core_msg.content if isinstance(tp, TextPart)
            )
        
        tool_response_collection_parts.append(Part.from_function_response(
            name=function_name,
            response={"content": tool_response_content_str} 
        ))

    if tool_response_collection_parts:
        vertex_content = Content(role="function", parts=tool_response_collection_parts)
    return vertex_content

def handle_tool_definition(tools: Sequence[ToolDefinition] | None) -> List[Tool] | None:
    if not tools:
        return 
    vertex_tools = []
    for tool_def in tools:
        params_dict = {
            "type": tool_def.function.parameters.type,
            "properties": tool_def.function.parameters.properties,
        }
        if tool_def.function.parameters.required is not None:
            params_dict["required"] = tool_def.function.parameters.required
        
        func_decl = FunctionDeclaration(
            name=tool_def.function.name,
            description=tool_def.function.description or "",
            parameters=params_dict
        )
        vertex_tools.append(Tool(function_declarations=[func_decl]))
    return vertex_tools

def convert_mode(tool_choice: str | dict) -> tuple[Optional[ToolConfig.FunctionCallingConfig.Mode],Optional[List[str]]]:
    mode: Optional[ToolConfig.FunctionCallingConfig.Mode] = None
    allowed_function_names: Optional[List[str]] = None

    if isinstance(tool_choice, str):
        match tool_choice:
            case "none":
                mode = ToolConfig.FunctionCallingConfig.Mode.NONE
            case "auto": 
                mode = ToolConfig.FunctionCallingConfig.Mode.AUTO
            case "required":
                mode = ToolConfig.FunctionCallingConfig.Mode.ANY
            case _: # Choice is a specific function name
                mode = ToolConfig.FunctionCallingConfig.Mode.ANY
                allowed_function_names = [tool_choice]
    
    elif isinstance(tool_choice, dict):
        if tool_choice.get("type") == "function":
            # Force a specific function call. It's not clear in OpenAI docs but shown in examples:
            # https://platform.openai.com/docs/guides/function-calling/function-calling-behavior?api-mode=chat#additional-configurations
            func_spec = tool_choice.get("function")
            if func_spec and isinstance(func_spec, dict) and "name" in func_spec:
                mode = ToolConfig.FunctionCallingConfig.Mode.ANY
                allowed_function_names = [func_spec["name"]]
            else:
                raise ValueError(f"Invalid tool_choice dict: {tool_choice}")
        else:
            raise ValueError(f"Unsupported tool_choice type in dict: {tool_choice.get('type')}")
    return mode, allowed_function_names

def convert_chat_request(req: ChatRequest) -> VertexGenerateRequest:
    vertex_contents: List[Content] = []
    # function names -> call IDs for resolving in ToolMessages
    tool_id_to_func_name_map: Dict[str, str] = {} 

    # Group messages by their type to handle consecutive ToolMessages correctly
    # OpenAI has ToolMessages as individual messages. Vertex expects them to be grouped
    # So groupby type which should allow us to iterate over consective ToolMessages
    for msg_type, group in groupby(req.messages, key=type):
        
        messages_in_group = list(group) 

        if msg_type is SystemMessage:
            for core_msg in messages_in_group: 
                system_message_text = '\n'.join(
                    content.text for content in core_msg.content if isinstance(content, TextPart)
                )
                vertex_contents.append(Content(role="user", parts=[Part.from_text(system_message_text)]))
                vertex_contents.append(Content(role="model", parts=[Part.from_text("Okay, I will follow these instructions.")]))
        
        elif msg_type is UserMessage:
            for core_msg in messages_in_group: 
                if isinstance(core_msg, UserMessage):
                    user_parts: List[Part] = [_part_to_vtx(part_data) for part_data in core_msg.content]
                    if user_parts:
                        vertex_contents.append(Content(role="user", parts=user_parts))
        
        elif msg_type is AssistantMessage:
            messages_in_group = cast(List[AssistantMessage], messages_in_group)
            contents = handle_assistant_messages(messages_in_group, tool_id_to_func_name_map)
            vertex_contents.extend(contents)                    
       
        elif msg_type is ToolMessage:
            messages_in_group = cast(List[ToolMessage], messages_in_group)
            content = handle_tool_messages(messages_in_group, tool_id_to_func_name_map)
            if content is not None:
                vertex_contents.append(content)                    

        else: # Should not happen if ChatMessage is a well-defined Union/base
            logger.warning(f"Unhandled message type in groupby: {msg_type}")

    #  Tool Definitions and Config 
    vertex_tools: Optional[List[Tool]] = handle_tool_definition(req.tools)

    vertex_tool_config: Optional[ToolConfig] = None
    if req.tool_choice:
        mode, allowed_function_names = convert_mode(req.tool_choice)
        if mode == ToolConfig.FunctionCallingConfig.Mode.ANY and not vertex_tools:
            raise ValueError("tool_choice 'required' but no tools provided.")
        
        if mode is not None:
            function_config_args: Dict[str, Any] = {"mode": mode}
            if allowed_function_names:
                function_config_args["allowed_function_names"] = allowed_function_names
            vertex_tool_config = ToolConfig(
                function_calling_config=ToolConfig.FunctionCallingConfig(**function_config_args)
            )

    elif vertex_tools:
        vertex_tool_config = ToolConfig(
            function_calling_config=ToolConfig.FunctionCallingConfig(
                mode=ToolConfig.FunctionCallingConfig.Mode.AUTO
                )
        )
    
    gen_config_params = {}
    if req.temperature is not None: 
        gen_config_params["temperature"] = req.temperature
    if req.max_tokens is not None: 
        gen_config_params["max_output_tokens"] = req.max_tokens
    if req.top_p is not None: 
        gen_config_params["top_p"] = req.top_p
    if req.stop:
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

    
    