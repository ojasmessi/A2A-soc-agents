"""
STEP 3 — The Threat-Intel agent's "brain", built as a LangGraph graph.

LangGraph models an agent as a GRAPH:
  * STATE  -> the data passed between steps. Here: a list of chat messages.
  * NODES  -> Python functions that read the state and return an update.
  * EDGES  -> which node runs next (fixed, or decided by a condition).

Our graph is the classic "ReAct" loop (Reason + Act):

        START
          |
          v
      [ agent ]  <-----------+      agent = ask the LLM what to do next
          |                  |
   wants a tool?             |
     yes /    \\ no           |
        v      v             |
   [ tools ]   END           |      tools = actually run the Python function(s)
        |                    |
        +--------------------+      ...then go back and let the LLM read the results
"""

import os

from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from .tools import ALL_TOOLS

SYSTEM_PROMPT = (
    "You are a Threat Intelligence analyst agent used by a SOC team. "
    "Always use your tools to look up IPs, CVEs and file hashes - never guess. "
    "Reply with a short, factual intel summary: each indicator, its verdict/score, "
    "and one line on why it matters. If a lookup returns nothing, say so."
)


def build_graph(llm=None):
    """Build and compile the LangGraph agent.

    `llm` can be injected (handy for tests); by default we use OpenAI via LangChain.
    """
    if llm is None:
        llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-5-mini"))

    # bind_tools() tells the LLM which tools exist (their names + JSON schemas)
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    # ---- NODE 1: the LLM decides (answer, or call a tool) ----
    async def agent_node(state: MessagesState):
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
        response = await llm_with_tools.ainvoke(messages)
        # Returning {"messages": [...]} APPENDS to the state (MessagesState has a reducer)
        return {"messages": [response]}

    # ---- NODE 2: run whatever tools the LLM asked for ----
    tool_node = ToolNode(ALL_TOOLS)

    # ---- wire the graph ----
    builder = StateGraph(MessagesState)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tool_node)

    builder.add_edge(START, "agent")
    # tools_condition looks at the last AI message:
    #   has tool_calls -> go to "tools", otherwise -> END
    builder.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    builder.add_edge("tools", "agent")

    # A checkpointer gives the graph MEMORY across calls that share a thread_id.
    # We will use the A2A "context_id" as the thread_id, so a multi-turn A2A
    # conversation remembers what was said before.
    return builder.compile(checkpointer=InMemorySaver())


# Quick manual test:  python -m threat_intel_agent.graph
if __name__ == "__main__":
    import asyncio

    from dotenv import load_dotenv

    load_dotenv()

    async def _demo():
        graph = build_graph()
        out = await graph.ainvoke(
            {"messages": [("user", "Is 185.220.101.1 malicious? Also what is CVE-2021-44228?")]},
            config={"configurable": {"thread_id": "demo"}},
        )
        for m in out["messages"]:
            m.pretty_print()  # shows every step: human -> AI tool call -> tool result -> AI answer

    asyncio.run(_demo())
