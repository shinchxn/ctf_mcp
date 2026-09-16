#!/usr/bin/env python3
"""
Gemini CTF Agent
================
AI-Powered reasoning agent for CTF challenges using Google Gemini API
and existing MCP (Model Context Protocol) CTF-Solver tools.

Target Architecture:
  User Prompt (CTF Challenge)
       ↓
  Gemini CTF Agent (gemini_agent.py)
       ↓ [System Prompt & CTF Instructions]
  Google Gemini API (google-genai SDK)
       ↕ [Tool Calls / Function Calling]
  MCP Server (src/my_server/mcp_server.py)
       ↕ [HTTP REST API]
  Kali Server (kali_server.py in Docker / Host)
       ↓
  Kali & CTF Tools (nmap, radare2, sqlmap, RsaCtfTool, checksec, etc.)
"""

import os
import sys
import argparse
import json
import logging
import inspect
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("gemini-ctf-agent")

# Attempt importing google-genai SDK
try:
    from google import genai
    from google.genai import types
except ImportError:
    logger.error("google-genai package is missing. Install via: pip install google-genai python-dotenv")
    sys.exit(1)

# Import existing MCP server and Kali client modules
try:
    from src.my_server.mcp_server import KaliToolsClient, setup_mcp_server, DEFAULT_KALI_SERVER, DEFAULT_REQUEST_TIMEOUT
except ImportError:
    # Handle path resolution if run directly from repo root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from src.my_server.mcp_server import KaliToolsClient, setup_mcp_server, DEFAULT_KALI_SERVER, DEFAULT_REQUEST_TIMEOUT


DEFAULT_SYSTEM_INSTRUCTION = """
You are the Gemini CTF Agent, an AI reasoning assistant specialized in solving authorized Capture The Flag (CTF) challenges, labs (PicoCTF, HackTheBox, TryHackMe), and intentionally vulnerable local lab targets.

You MUST follow these strict operational rules:

1. CTF CATEGORY IDENTIFICATION:
   First identify the category: Web, Pwn/Binary Exploitation, Reverse Engineering, Cryptography, Forensics, Steganography, OSINT, Misc, Network/PCAP, Mobile, or Other.

2. HYPOTHESIS-DRIVEN REASONING:
   - Form an explicit hypothesis BEFORE executing any tool call.
   - Select the single minimum useful tool needed for your hypothesis. Do NOT run tools randomly.

3. STRUCTURED LOGGING & EXPO:
   Maintain a clean trace for your reasoning steps:
   - Observation: Current evidence / tool output
   - Hypothesis: What you suspect
   - Tool Selected: Specific MCP tool
   - Tool Input: Input parameters
   - Result: Execution result
   - Interpretation: What the result proves or disproves
   - Next Action: Next step

4. VERIFIABLE FLAGS ONLY:
   - When a candidate flag is found, verify it against the challenge context.
   - Do NOT assume a string is correct just because it matches a flag regex format. Explain the supporting evidence.
   - Never fabricate, hallucinate, or claim a flag was found unless it was directly observed in tool outputs or derived from verifiable challenge data.

5. SAFETY & SCOPE:
   - All tool executions MUST remain strictly within authorized challenge scope.
   - Never attack arbitrary third-party systems outside the provided CTF challenge targets.

6. FAILURE RECOVERY:
   - If a tool call or path fails, explain why based on empirical log evidence and try a different evidence-based approach.
"""


def load_system_instruction(custom_prompt_file: Optional[str] = None) -> str:
    """Load system instructions from PROBLEM_SOLVING_PROMPTS.md or default string."""
    prompt_file = custom_prompt_file or os.path.join(os.path.dirname(__file__), "PROBLEM_SOLVING_PROMPTS.md")
    if os.path.exists(prompt_file):
        try:
            with open(prompt_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Return system instruction section or full content
                return content
        except Exception as e:
            logger.warning(f"Could not read prompt file {prompt_file}: {e}")
    return DEFAULT_SYSTEM_INSTRUCTION


class GeminiCTFAgent:
    """Agent bridging Gemini API to MCP Kali tools for CTF solving."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gemini-2.5-flash",
        server_url: str = DEFAULT_KALI_SERVER,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
        max_turns: int = 25
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("GEMINI_API_KEY is not set.")
            logger.error("Please get an API key from https://aistudio.google.com/ and set GEMINI_API_KEY in your environment or .env file.")
            sys.exit(1)

        self.model_name = model_name
        self.server_url = server_url
        self.timeout = timeout
        self.max_turns = max_turns

        # Initialize Gemini Client
        self.genai_client = genai.Client(api_key=self.api_key)

        # Initialize Kali Tools & FastMCP Server instance in-process
        logger.info(f"Connecting to Kali API Server at: {self.server_url}")
        self.kali_client = KaliToolsClient(self.server_url, self.timeout)
        self.mcp_server = setup_mcp_server(self.kali_client)

        # Build tool registry and function declarations
        self.tool_map = {}
        self.function_declarations = []
        self._register_mcp_tools()

    def _register_mcp_tools(self):
        """Extract tool definitions from FastMCP server and convert to Gemini FunctionDeclarations."""
        tool_manager = getattr(self.mcp_server, "_tool_manager", None)
        if not tool_manager:
            logger.warning("Could not access FastMCP tool manager directly. Fallback to registered tools.")
            return

        # List all registered FastMCP tools
        tools_dict = getattr(tool_manager, "_tools", {})
        logger.info(f"Discovered {len(tools_dict)} tools from MCP server.")

        for name, tool_obj in tools_dict.items():
            fn = getattr(tool_obj, "fn", None)
            description = getattr(tool_obj, "description", "") or (fn.__doc__ if fn else "")
            
            # Store executable function in map
            self.tool_map[name] = fn

            # Extract schema properties
            args_model = getattr(tool_obj, "args_model", None)
            parameters_schema = {"type": "OBJECT", "properties": {}}

            if args_model and hasattr(args_model, "model_json_schema"):
                try:
                    schema = args_model.model_json_schema()
                    props = schema.get("properties", {})
                    req = schema.get("required", [])

                    gemini_props = {}
                    for prop_name, prop_data in props.items():
                        p_type = prop_data.get("type", "string").upper()
                        if p_type == "INTEGER":
                            g_type = "INTEGER"
                        elif p_type == "BOOLEAN":
                            g_type = "BOOLEAN"
                        elif p_type == "NUMBER":
                            g_type = "NUMBER"
                        elif p_type == "ARRAY":
                            g_type = "ARRAY"
                        else:
                            g_type = "STRING"

                        gemini_props[prop_name] = {
                            "type": g_type,
                            "description": prop_data.get("description", prop_data.get("title", ""))
                        }

                    parameters_schema = {
                        "type": "OBJECT",
                        "properties": gemini_props,
                        "required": req
                    }
                except Exception as e:
                    logger.debug(f"Schema conversion fallback for tool {name}: {e}")

            # Build Gemini FunctionDeclaration
            func_decl = types.FunctionDeclaration(
                name=name,
                description=description.strip() if description else f"Execute {name}",
                parameters=parameters_schema if parameters_schema["properties"] else None
            )
            self.function_declarations.append(func_decl)

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool using registered MCP tool handler."""
        if tool_name not in self.tool_map:
            return {"error": f"Tool '{tool_name}' not found in MCP tool registry."}

        fn = self.tool_map[tool_name]
        logger.info(f"🔨 [MCP Tool Call] {tool_name}({args})")
        try:
            # If function expects kwargs
            sig = inspect.signature(fn)
            valid_args = {k: v for k, v in args.items() if k in sig.parameters}
            result = fn(**valid_args)
            return result
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {"error": str(e), "success": False}

    def solve(self, challenge_description: str, file_paths: Optional[List[str]] = None) -> str:
        """Run iterative reasoning loop to solve the CTF challenge."""
        system_instruction = load_system_instruction()
        
        prompt = f"CTF CHALLENGE TASK:\n{challenge_description}\n"
        if file_paths:
            prompt += f"\nATTACHED CHALLENGE FILES:\n" + "\n".join(f"- {p}" for p in file_paths)
            prompt += "\nUse session file management tools (create_analysis_session, upload_binary) if needed to analyze these artifacts.\n"

        logger.info(f"Starting Gemini CTF Agent solver for challenge...")

        # Setup Gemini tool list
        gemini_tools = [types.Tool(function_declarations=self.function_declarations)]

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=gemini_tools,
            temperature=0.2,  # Low temperature for precise reasoning
        )

        contents = [types.Content(role="user", parts=[types.Part.from_text(text=prompt)])]

        turn = 0
        while turn < self.max_turns:
            turn += 1
            logger.info(f"--- Reason Step {turn}/{self.max_turns} ---")

            response = self.genai_client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )

            # Append model candidate response to context
            if response.candidates:
                candidate = response.candidates[0]
                contents.append(candidate.content)

                # Check if model generated text output
                if response.text:
                    print(f"\n🧠 [Gemini Reasoning Step {turn}]\n{response.text}\n")

                # Check for tool function calls
                function_calls = response.function_calls
                if not function_calls:
                    # Model did not call any tools, completed reasoning
                    logger.info("Agent concluded reasoning. Returning final output.")
                    return response.text or "Challenge analysis complete."

                # Process tool calls
                response_parts = []
                for call in function_calls:
                    tool_name = call.name
                    tool_args = dict(call.args) if call.args else {}
                    
                    tool_output = self.execute_tool(tool_name, tool_args)
                    
                    # Convert result to string or dict response part
                    resp_dict = tool_output if isinstance(tool_output, dict) else {"result": str(tool_output)}
                    response_parts.append(
                        types.Part.from_function_response(
                            name=tool_name,
                            response=resp_dict
                        )
                    )

                # Append tool execution results as user response
                contents.append(types.Content(role="user", parts=response_parts))

            else:
                logger.warning("No candidate generated by Gemini.")
                break

        return "Reached maximum reasoning turns limit."


def main():
    parser = argparse.ArgumentParser(description="Gemini CTF Agent — AI Reasoning Layer for CTF-Solver")
    parser.add_argument("challenge", type=str, nargs="?", help="Challenge description or prompt")
    parser.add_argument("--files", "-f", nargs="+", help="Attached challenge file paths")
    parser.add_argument("--model", type=str, default=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"), help="Gemini model name (default: gemini-2.5-flash)")
    parser.add_argument("--server", type=str, default=os.environ.get("KALI_SERVER_URL", DEFAULT_KALI_SERVER), help="Kali Server API URL (default: http://localhost:5000)")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("KALI_REQUEST_TIMEOUT", str(DEFAULT_REQUEST_TIMEOUT))), help="Tool execution timeout in seconds")
    parser.add_argument("--max-turns", type=int, default=25, help="Maximum reasoning turns (default: 25)")
    
    args = parser.parse_args()

    if not args.challenge:
        print("🛡️ Gemini CTF Agent")
        print("--------------------")
        args.challenge = input("Enter CTF Challenge Description: ").strip()
        if not args.challenge:
            print("No challenge provided. Exiting.")
            sys.exit(0)

    agent = GeminiCTFAgent(
        model_name=args.model,
        server_url=args.server,
        timeout=args.timeout,
        max_turns=args.max_turns
    )

    result = agent.solve(args.challenge, file_paths=args.files)
    print("\n================ FINAL SOLUTION / SUMMARY ================")
    print(result)
    print("==========================================================")


if __name__ == "__main__":
    main()
