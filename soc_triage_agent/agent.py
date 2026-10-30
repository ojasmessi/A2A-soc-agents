"""
STEP 6 — The SOC-Triage agent, built with Google ADK (Agent Development Kit).

This is the "orchestrator". It:
  * runs on OpenAI (through LiteLLM, because ADK's default models are Gemini)
  * has its own local tool (score_alert_severity)
  * talks to the LangGraph Threat-Intel agent over A2A using RemoteA2aAgent

ADK convention: a folder with __init__.py + agent.py that defines `root_agent`.
That lets you run it with the ADK CLI:
    adk web            (browser dev UI - run from the project root)
    adk run soc_triage_agent   (terminal chat)
"""

import os

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH, RemoteA2aAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools.agent_tool import AgentTool

load_dotenv()

MODEL = LiteLlm(model=f"openai/{os.getenv('OPENAI_MODEL', 'gpt-5-mini')}")  # "provider/model" format
INTEL_URL = f"http://{os.getenv('THREAT_INTEL_HOST', 'localhost')}:{os.getenv('THREAT_INTEL_PORT', '10001')}"


# ------------------------------------------------------------------
# 1) A local tool. In ADK a tool is a plain function; ADK reads the
#    name, type hints and docstring to build the schema for the LLM.
# ------------------------------------------------------------------
def score_alert_severity(threat_score: int, asset_criticality: str, exploited_in_wild: bool) -> dict:
    """Compute a triage severity for a security alert.

    Args:
        threat_score: Threat/risk score of the indicator from 0 to 100 (use 0 if unknown).
        asset_criticality: How important the affected asset is: "low", "medium" or "high".
        exploited_in_wild: True if the related vulnerability/indicator is actively exploited.

    Returns:
        dict with the numeric score, the severity label and the recommended SLA.
    """
    weight = {"low": 1.0, "medium": 1.5, "high": 2.0}.get(asset_criticality.lower(), 1.0)
    score = min(100, int(threat_score * weight * 0.5 + (30 if exploited_in_wild else 0)))
    if score >= 80:
        label, sla = "P1 - Critical", "respond within 15 minutes"
    elif score >= 60:
        label, sla = "P2 - High", "respond within 1 hour"
    elif score >= 30:
        label, sla = "P3 - Medium", "respond within 8 hours"
    else:
        label, sla = "P4 - Low", "respond within 24 hours"
    return {"severity_score": score, "severity": label, "sla": sla}


# ------------------------------------------------------------------
# 2) The REMOTE agent. RemoteA2aAgent downloads the agent card from the
#    URL, then forwards messages to that agent using the A2A protocol.
#    To ADK it looks like any other agent - it doesn't care that the
#    other side is LangGraph (that's the whole point of A2A).
# ------------------------------------------------------------------
threat_intel_agent = RemoteA2aAgent(
    name="threat_intel_agent",
    description="Remote threat-intel agent (LangGraph). Looks up IP reputation, CVE details and file hash verdicts.",
    agent_card=f"{INTEL_URL}{AGENT_CARD_WELL_KNOWN_PATH}",
)


# ------------------------------------------------------------------
# 3) The root agent. We wrap the remote agent in AgentTool so the
#    orchestrator CALLS it like a tool and keeps control afterwards
#    (it can then score severity and write the final triage note).
#    Alternative: sub_agents=[threat_intel_agent] = full hand-off.
# ------------------------------------------------------------------
root_agent = Agent(
    name="soc_triage_agent",
    model=MODEL,
    description="SOC Tier-1 triage assistant that enriches alerts and assigns a severity.",
    instruction=(
        "You are a SOC Tier-1 triage assistant.\n"
        "When the user gives you an alert or indicators (IPs, CVEs, hashes):\n"
        "1. Call the `threat_intel_agent` tool with the indicators to get threat intel.\n"
        "2. Call `score_alert_severity` using the intel (threat score, exploited_in_wild) "
        "and the asset criticality the user mentions (assume 'medium' if not given).\n"
        "3. Reply with a triage note: Summary, Intel findings, Severity + SLA, "
        "and 2-3 recommended next actions.\n"
        "For general questions that need no intel, just answer directly."
    ),
    tools=[score_alert_severity, AgentTool(agent=threat_intel_agent)],
)
