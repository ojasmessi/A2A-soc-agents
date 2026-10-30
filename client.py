"""
STEP 8 — A plain A2A client (no ADK, no LangGraph): talk to ANY A2A agent.

    python client.py                         # talks to the intel agent (10001)
    python client.py http://localhost:10002  # talks to the ADK triage agent
    python client.py http://localhost:10001 "Is 45.95.147.236 bad?"

What happens:
  1. Fetch the agent card from <url>/.well-known/agent-card.json  (DISCOVERY)
  2. Build a Message (role=user, one text Part)
  3. send_message() -> stream of responses: Task, status updates, artifacts
"""

import asyncio
import sys
import uuid

import httpx
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import get_stream_response_text, new_text_message
from a2a.types import Role, SendMessageRequest, TaskState

DEFAULT_URL = "http://localhost:10001"
DEFAULT_QUESTION = (
    "Alert: 50 failed SSH logins from 185.220.101.1 on our web server, "
    "which runs a Log4j app (CVE-2021-44228). Give me the intel."
)


async def main(url: str, question: str) -> None:
    # httpx's default timeout is 5 seconds - far too short for an LLM agent that
    # calls OpenAI several times. Give it up to 5 minutes per request.
    http = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))
    card = await A2ACardResolver(http, url).get_agent_card()   # 1. DISCOVERY: fetch the agent card
    client = await create_client(card, client_config=ClientConfig(httpx_client=http))  # client reuses our http
    print(f"Connected to agent: {card.name} - {card.description}")
    print(f"Skills: {[s.name for s in card.skills]}\n")

    context_id = str(uuid.uuid4())                          # one conversation thread
    msg = new_text_message(question, context_id=context_id, role=Role.ROLE_USER)  # 2.

    async for response in client.send_message(SendMessageRequest(message=msg)):  # 3.
        kind = response.WhichOneof("payload")               # task | message | status_update | artifact_update
        text = get_stream_response_text(response)
        if kind == "status_update":
            state = TaskState.Name(response.status_update.status.state)  # e.g. TASK_STATE_WORKING
            print(f"[status] {state}  {text}")
        elif text:
            print(f"[{kind}]\n{text}\n")
    await client.close()
    await http.aclose()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    question = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_QUESTION
    asyncio.run(main(url, question))
