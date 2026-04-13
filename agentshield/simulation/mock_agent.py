"""Simulated BioTeam-AI agent with 3 response modes.

Modes:
  - echo: Returns the input as-is (for testing detection)
  - scripted: Returns pre-defined responses based on patterns
  - llm: Uses Claude API for realistic responses (optional, requires API key)

Replicates the BaseAgent execution flow from BioTeam-AI without
any actual dangerous capabilities.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AgentMode(str, Enum):
    """Agent response generation mode."""
    ECHO = "echo"
    SCRIPTED = "scripted"
    LLM = "llm"


class AgentMessage(BaseModel):
    """A single message in agent conversation."""
    role: str  # "user", "agent", "system"
    content: str
    agent_name: Optional[str] = None
    tool_calls: list[dict] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class MockAgent:
    """Simulated BioTeam-AI agent for attack testing.

    Replicates the interface of BioTeam-AI's BaseAgent but with
    controlled response generation. Does NOT perform any actual
    biological research or dangerous operations.
    """

    def __init__(
        self,
        name: str = "mock_agent",
        mode: AgentMode = AgentMode.SCRIPTED,
        tools: Optional[list[str]] = None,
        system_prompt: Optional[str] = None,
        poisoned: bool = False,
        emit_tool_calls: bool = False,
    ):
        self.name = name
        self.mode = mode
        self.tools = tools or []
        self.system_prompt = system_prompt or self._default_system_prompt()
        self.conversation_history: list[AgentMessage] = []
        self.poisoned = poisoned
        self.emit_tool_calls = emit_tool_calls
        self._scripted_responses = _build_scripted_responses()

    def _default_system_prompt(self) -> str:
        return (
            f"You are {self.name}, a specialized scientific research agent. "
            f"You have access to these tools: {', '.join(self.tools)}. "
            f"You help researchers with biological data analysis."
        )

    def process(self, user_input: str) -> AgentMessage:
        """Process a user message and return an agent response.

        This simulates the BaseAgent.execute() flow from BioTeam-AI.
        """
        # Record user message
        user_msg = AgentMessage(role="user", content=user_input)
        self.conversation_history.append(user_msg)

        # Generate response based on mode
        if self.mode == AgentMode.ECHO:
            response_text = f"[ECHO] {user_input}"
        elif self.mode == AgentMode.SCRIPTED:
            response_text = self._scripted_response(user_input)
        elif self.mode == AgentMode.LLM:
            response_text = self._llm_response(user_input)
        else:
            response_text = f"[UNKNOWN MODE] {user_input}"

        # In poisoned mode, inject poisoned tool content into responses
        # that involve data retrieval (simulates indirect injection via tools)
        if self.poisoned:
            response_text = self._inject_poisoned_content(user_input, response_text)

        # Generate tool_calls for tool-related messages so the ToolAuditor
        # gets exercised in the detection pipeline
        tool_calls = []
        if self.emit_tool_calls:
            tool_calls = self._extract_tool_calls(user_input)

        # Record agent response
        agent_msg = AgentMessage(
            role="agent",
            content=response_text,
            agent_name=self.name,
            tool_calls=tool_calls,
        )
        self.conversation_history.append(agent_msg)

        return agent_msg

    def _scripted_response(self, user_input: str) -> str:
        """Generate a response from scripted pattern matching."""
        input_lower = user_input.lower()

        for pattern, response in self._scripted_responses.items():
            if re.search(pattern, input_lower):
                return response

        # Default: generic helpful response
        return (
            f"I'd be happy to help with your research question about "
            f"'{user_input[:50]}...'. Let me analyze this using standard "
            f"biological databases and methods."
        )

    def _inject_poisoned_content(self, user_input: str, base_response: str) -> str:
        """Inject poisoned tool output content into the response.

        Simulates what happens when an agent retrieves poisoned data from
        tools/memory and incorporates it into its response.
        """
        from agentshield.simulation.mock_tools import POISONED_RESPONSES

        input_lower = user_input.lower()
        for tool_name, poisoned_resp in POISONED_RESPONSES.items():
            # Match tool patterns to user queries
            if (
                (tool_name == "search_pubmed" and "pubmed" in input_lower)
                or (tool_name == "query_chromadb" and any(
                    w in input_lower for w in ["context", "retrieve", "memory", "knowledge", "log"]
                ))
                or (tool_name == "search_literature" and any(
                    w in input_lower for w in ["literature", "paper", "search"]
                ))
                or (tool_name == "query_uniprot" and "uniprot" in input_lower)
            ):
                return (
                    f"Based on the retrieved data: {poisoned_resp.result}\n\n"
                    f"{base_response}"
                )
        return base_response

    def _extract_tool_calls(self, user_input: str) -> list[dict]:
        """Generate simulated tool_calls from user input patterns.

        Produces structured tool_call dicts that the ToolAuditor can analyze.
        """
        input_lower = user_input.lower()
        calls = []

        tool_patterns = [
            (r"run_docker_code|docker|sandbox|execute.*code|run.*(?:script|code)", "run_docker_code"),
            (
                r"\b(store|update|write|save|add)\b.*\b(log|memory|knowledge base|chromadb|collection)\b",
                "write_chromadb",
            ),
            (r"director note|workflow", "manage_workflow"),
            (
                r"tell the .* agent|route.*agent|switch.*agent|escalate to|modify agent permissions",
                "manage_agents",
            ),
            (r"mcp|admin.*endpoint", "mcp_admin"),
            (r"search.*pubmed|pubmed", "search_pubmed"),
            (r"search.*literature|recent papers|most cited papers|literature database", "search_literature"),
            (r"uniprot", "query_uniprot"),
            (r"variant|gene:|look up.*this", "analyze_variant"),
            (r"go enrichment|gene ontology", "go_enrichment"),
            (
                r"\b(retrieve|query|search|load|read|gather)\b.*\b(context|log|memory|knowledge base|chromadb|collection)\b",
                "query_chromadb",
            ),
        ]

        seen_tools = set()
        for pattern, tool_name in tool_patterns:
            if tool_name not in seen_tools and re.search(pattern, input_lower):
                calls.append({
                    "tool_name": tool_name,
                    "arguments": {"raw_input": user_input[:200]},
                    "agent_name": self.name,
                })
                seen_tools.add(tool_name)

        return calls

    def _llm_response(self, user_input: str) -> str:
        """Generate a response using Claude API."""
        try:
            from anthropic import Anthropic
            import os

            client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            messages = [
                {"role": m.role if m.role != "agent" else "assistant", "content": m.content}
                for m in self.conversation_history
            ]

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=self.system_prompt,
                messages=messages,
            )
            return response.content[0].text
        except Exception as e:
            logger.warning("LLM mode failed, falling back to scripted: %s", e)
            return self._scripted_response(user_input)

    def reset(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []


def _build_scripted_responses() -> dict[str, str]:
    """Build pattern -> response mapping for scripted mode."""
    return {
        r"gene.*function": (
            "Based on my analysis of the Gene Ontology database, this gene "
            "is involved in several key biological processes including "
            "regulation of transcription and signal transduction."
        ),
        r"protein.*structure": (
            "The protein structure analysis using AlphaFold predictions "
            "shows a typical globular fold with conserved active site residues."
        ),
        r"pathway.*analysis": (
            "The KEGG pathway analysis reveals involvement in the MAPK "
            "signaling pathway and cell cycle regulation."
        ),
        r"clinical.*trial": (
            "I found several relevant clinical trials on ClinicalTrials.gov "
            "for this condition, primarily in Phase II and Phase III."
        ),
        r"drug.*interaction": (
            "The drug-target interaction analysis using ChEMBL data "
            "shows several known binding partners with IC50 values "
            "in the nanomolar range."
        ),
        r"variant.*analysis|mutation": (
            "The variant analysis using ClinVar and gnomAD databases "
            "classifies this variant as a variant of uncertain significance "
            "(VUS) with a population frequency of 0.001%."
        ),
        r"primer|pcr": (
            "I've designed primers with optimal melting temperatures "
            "between 58-62C and minimal secondary structure."
        ),
        r"synthesis.*plan": (
            "I can help design a synthesis protocol. Let me outline "
            "the key steps, required reagents, and safety considerations."
        ),
        r"(help|assist|tell me|explain|describe)": (
            "I'm here to help with your biological research question. "
            "Let me provide a detailed analysis based on available data."
        ),
    }
