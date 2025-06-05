import json
from itertools import groupby
from functools import singledispatch
from typing import List, Tuple, Sequence, Optional, Literal, Union, Dict, cast

from ..core.chat_schema import (
    ChatRequest,
    Message,
    AssistantMessage,
    UserMessage,
    ToolMessage,
    SystemMessage,
    TextPart,
    ImagePart,
    FilePart,
    ToolCall,
    ToolDefinition
)
from ..core.embed_schema import EmbeddingRequest

import app.providers.bedrock.converse_schemas as br 
from app.providers.bedrock.cohere_embedding_schemas import CohereRequest

AgentMessage = AssistantMessage | UserMessage | ToolMessage

def convert_core_role(role: Literal['assistant', 'user', 'tool']) -> br.BedrockMessageRole:
    # Bedrock does not have a 'tool' role. Those should be passed in as 'user'
    return "assistant" if role == "assistant" else "user"

def extract_system_messages(messages:Sequence[Message]) -> Tuple[Optional[List[SystemMessage]], List[AgentMessage]]:
    system: Optional[Sequence[SystemMessage]]  = []
    other: Sequence[AgentMessage] = []
    for m in messages:
        if m.role == "system":
            system.append(m)
        else:
            other.append(m)
    if len(system) == 0: 
        system = None
    return system, other

def tool_def_to_br(td: ToolDefinition) -> br.ToolItem:
    return br.ToolItem(
        tool_spec=br.ToolSpecification(
            name=td.function.name,
            description=td.function.description,
            input_schema=br.ToolInputSchema(
                json=td.function.parameters.model_dump()
            ),
        )
    )


def tool_choice_to_br(choice: Union[str, Dict[str, Dict[str, str]]] | None) -> br.ToolChoice | None:
    if choice is None:
        return None

    if isinstance(choice, str):
        match choice:
            case "auto":
                return {"auto": {}}
            case "none":
                # Not in Bedrock;  omit the field.
                return None
            case "required" | "any":
                return {"any": {}}
            case _:
                raise ValueError(f"Unsupported tool_choice string: {choice}")
    if (
        choice.get("type") == "function"
        and isinstance(choice.get("function"), dict)
        and "name" in choice["function"]
    ):
        return {"tool": {"name": choice["function"]["name"]}}

    raise ValueError("Malformed tool_choice object")


## Handle various block type conversions
@singledispatch
def _part_to_br(part) -> br.ContentBlock:
    raise TypeError(f"No converter for {type(part)}")

@_part_to_br.register
def _(part: TextPart) -> br.ContentTextBlock:
    return br.ContentTextBlock(text=part.text)

@_part_to_br.register
def _(part: ImagePart) -> br.ContentImageBlock:
    return br.ContentImageBlock(
        image=br.ImagePayload(
            format="jpeg",
            source=br.ImageSource(bytes=part.bytes_)
        )
    )

@_part_to_br.register
def _(part: FilePart) -> br.ContentDocumentBlock:
    return br.ContentDocumentBlock(
        document=br.DocumentPayload(
            format="pdf",
            name=part.name or "Untitled",
            source=br.DocumentSource(bytes=part.bytes_)
        )
    )

@_part_to_br.register
def _(tc: ToolCall) -> br.ToolUseBlock:
    args = {}
    try:
        args = json.loads(tc.function.arguments)
    except json.JSONDecodeError:
        pass
    return br.ToolUseBlock(
        tool_use=br.ToolUseBlockContent(
            tool_use_id=tc.id,
            name=tc.function.name,
            input=args,
        )
    )


@_part_to_br.register
def _(tm: ToolMessage) -> br.ToolResultBlock:
    # only text & json supported here; expand as needed
    content_blocks: list[br.ContentBlock | br.ContentJSONBlock] = []
    for part in tm.content if isinstance(tm.content, list) else [tm.content]:
        if isinstance(part, TextPart):
            content_blocks.append(br.ContentTextBlock(text=part.text))
        else: # raw string / JSON
            content_blocks.append(br.ContentJSONBlock(json=part))  

    return br.ToolResultBlock(
        tool_result=br.ToolResultBlockContent(
            tool_use_id=tm.tool_call_id,
            content=content_blocks,
        )
    )


def core_to_bedrock(req: ChatRequest) -> br.ConverseRequest:
    '''
    The primary conversion routine. It takes a ChatRequest
    passed in the core format and translates it to a request
    appropriate to pass to Bedrock's Converse API.
    '''
    system_messages, messages = extract_system_messages(req.messages)
    if system_messages is not None:
        system_messages = [
            br.SystemContentBlock(text=p.text) 
            for m in system_messages for p in m.content
        ]

    tool_cfg = None
    if req.tools:
        tool_cfg = br.ToolConfig(
            tools=[tool_def_to_br(td) for td in req.tools],
            tool_choice=tool_choice_to_br(req.tool_choice)
        )
        
    inference_config = None
    if any(i is not None for i in (req.max_tokens, req.temperature, req.top_p, req.stop)):
        inference_config = br.InferenceConfig(
            max_tokens=req.max_tokens,
            temperature=req.temperature,
            top_p=req.top_p,
            stop_sequences=req.stop
        )
    
    br_messages: list[br.Message] = []

    for message_type, group in groupby(messages, type):
        messages_in_group = list(group)

        if message_type == UserMessage:
            for core_msg in messages_in_group:
                content_blocks = [_part_to_br(p) for p in core_msg.content]
                if content_blocks:
                        br_messages.append(br.Message(role="user", content=content_blocks))

        elif message_type == AssistantMessage:
            for core_msg in messages_in_group:
                core_msg = cast(AssistantMessage, core_msg, )
                assistant_content_blocks: List[br.ContentBlock] = []
                if core_msg.content: # Handle text/image from assistant
                    for part_data in core_msg.content:
                        assistant_content_blocks.append(_part_to_br(part_data))
                
                if core_msg.tool_calls: # Assistant asking to run a tool
                    for tc in core_msg.tool_calls:
                        assistant_content_blocks.append(_part_to_br(tc)) 
                
                if assistant_content_blocks:
                    br_messages.append(br.Message(role="assistant", content=assistant_content_blocks))
        
        elif message_type == ToolMessage:
            all_tool_result_blocks: List[br.ContentBlock] = [] # Collect all ToolResultBlocks
            for core_msg in messages_in_group:
                all_tool_result_blocks.append(_part_to_br(core_msg)) 
            
            if all_tool_result_blocks:
                # Bedrock expects tool results in a 'user' role message.
                br_messages.append(br.Message(role="user", content=all_tool_result_blocks))

    return br.ConverseRequest(
        model_id=req.model,
        messages=br_messages,
        system=system_messages, 
        inference_config=inference_config,
        tool_config=tool_cfg
    )


def core_embed_request_to_bedrock(req: EmbeddingRequest) -> CohereRequest:
    return CohereRequest(
        model=req.model,
        texts=req.input,
        input_type=req.input_type, # type: ignore[arg-type]
        embedding_types=[req.encoding_format]
    )
