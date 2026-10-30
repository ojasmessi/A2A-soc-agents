"""
STEP 5 — Serve the LangGraph agent over A2A.

Two things make an agent an "A2A agent":
  1. An AGENT CARD: a public JSON "business card" served at
        http://HOST:PORT/.well-known/agent-card.json
     It says who the agent is, what skills it has, and the URL to talk to it.
  2. A JSON-RPC ENDPOINT that accepts A2A methods like SendMessage / SendStreamingMessage.

Run it:   python -m threat_intel_agent.server
Then open http://localhost:10001/.well-known/agent-card.json in your browser.
"""

import logging
import os

import uvicorn
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from dotenv import load_dotenv
from starlette.applications import Starlette

from .executor import ThreatIntelExecutor

load_dotenv()
logging.basicConfig(level=logging.INFO)

HOST = os.getenv("THREAT_INTEL_HOST", "localhost")
PORT = int(os.getenv("THREAT_INTEL_PORT", "10001"))


def build_agent_card() -> AgentCard:
    skill = AgentSkill(
        id="threat_intel_lookup",
        name="Threat intelligence lookup",
        description="Reputation for IP addresses, details for CVEs and verdicts for file hashes.",
        tags=["security", "threat-intel", "soc", "ioc"],
        examples=[
            "Is 185.220.101.1 malicious?",
            "What is CVE-2021-44228?",
            "Check hash 44d88612fea8a8f36de82e1278abb02f",
        ],
    )
    return AgentCard(
        name="threat_intel_agent",
        description="LangGraph agent that enriches IOCs (IPs, CVEs, hashes) with threat intelligence.",
        version="1.0.0",
        # WHERE and HOW to reach this agent (A2A v1 lists interfaces instead of one url)
        supported_interfaces=[
            AgentInterface(url=f"http://{HOST}:{PORT}/", protocol_binding="JSONRPC", protocol_version="1.0")
        ],
        capabilities=AgentCapabilities(streaming=True),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[skill],
    )


def build_app() -> Starlette:
    card = build_agent_card()
    handler = DefaultRequestHandler(
        agent_executor=ThreatIntelExecutor(),  # our LangGraph adapter
        task_store=InMemoryTaskStore(),         # remembers tasks while the server runs
        agent_card=card,
    )
    return Starlette(
        routes=[
            *create_agent_card_routes(card),  # GET /.well-known/agent-card.json
            # POST /  (JSON-RPC). v0.3 compat lets older A2A clients talk to us too.
            *create_jsonrpc_routes(handler, "/", enable_v0_3_compat=True),
        ]
    )


app = build_app()

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
