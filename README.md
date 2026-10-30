# A2A SOC Agents — Google ADK + LangGraph

Two AI agents built with different frameworks that talk over the **A2A (Agent-to-Agent)** protocol, both powered by OpenAI.

| Agent | Framework | Port | Job |
|---|---|---|---|
| `threat_intel_agent` | LangChain + LangGraph (served with `a2a-sdk`) | 10001 | Looks up IPs, CVEs, file hashes |
| `soc_triage_agent` | Google ADK (OpenAI via LiteLLM) | 10002 (optional) | Calls the intel agent over A2A, scores severity, writes a triage note |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then paste your OPENAI_API_KEY
python step1_hello_llm.py                             # sanity check

# Terminal 1
python -m threat_intel_agent.server
# Terminal 2
python client.py                                      # plain A2A client -> LangGraph agent
adk web                                               # chat with the ADK agent (http://localhost:8000)
# Optional, Terminal 3: expose the ADK agent over A2A, then
python serve_triage_a2a.py
python client.py http://localhost:10002 "Alert: SSH brute force from 185.220.101.1"
```

## Build order (each file is commented for beginners)

1. `step1_hello_llm.py` — LangChain + OpenAI
2. `threat_intel_agent/tools.py` — `@tool` functions (mock intel data)
3. `threat_intel_agent/graph.py` — LangGraph ReAct graph with memory
4. `threat_intel_agent/executor.py` — A2A `AgentExecutor`
5. `threat_intel_agent/server.py` — agent card + JSON-RPC server
6. `soc_triage_agent/agent.py` — ADK agent + `RemoteA2aAgent`
7. `serve_triage_a2a.py` — `to_a2a()` one-liner
8. `client.py` — framework-free A2A client

Tested with google-adk 2.13.0, a2a-sdk 1.3.0, langgraph 1.2.18, langchain 1.4.7 (Oct 2026).
