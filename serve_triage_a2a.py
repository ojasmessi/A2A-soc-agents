"""
STEP 7 — Expose the ADK agent itself over A2A (so OTHER agents can call it).

to_a2a() does everything from steps 4-5 for you:
  * auto-builds an agent card from the agent's name/description/tools
  * wraps the agent in an A2A AgentExecutor
  * returns a Starlette web app

Run:  python serve_triage_a2a.py
Card: http://localhost:10002/.well-known/agent-card.json
Now the chain is:  client --A2A--> ADK triage agent --A2A--> LangGraph intel agent
"""

import os

import uvicorn
from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a

from soc_triage_agent.agent import root_agent

load_dotenv()
PORT = int(os.getenv("TRIAGE_PORT", "10002"))

app = to_a2a(root_agent, host="localhost", port=PORT)

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=PORT)
