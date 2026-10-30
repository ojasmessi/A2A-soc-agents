"""
STEP 4 — The A2A "AgentExecutor": the adapter between the A2A protocol and LangGraph.

The a2a-sdk server handles all the HTTP / JSON-RPC plumbing. It only asks you
for ONE class with two methods:

    execute(context, event_queue)  -> do the work, publish events
    cancel(context, event_queue)   -> stop the work

A2A vocabulary you meet here:
  * Message   - one turn of conversation (role = user or agent) made of Parts
  * Part      - a piece of content: text, data (JSON), file/url, raw bytes
  * Task      - a unit of work with an id and a STATE (submitted -> working -> completed/failed/...)
  * Artifact  - the RESULT/output a task produces (also made of Parts)
  * context_id- groups several tasks/messages into one conversation (like a chat thread)

The executor publishes events on the event_queue; the SDK turns them into
JSON-RPC responses (or a live SSE stream if the client asked for streaming).
"""

import logging

from a2a.helpers import new_task, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import TaskState
from langchain_core.messages import HumanMessage

from .graph import build_graph

log = logging.getLogger(__name__)


class ThreatIntelExecutor(AgentExecutor):
    def __init__(self, graph=None):
        # build the LangGraph once and reuse it for every request
        self.graph = graph or build_graph()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        user_text = context.get_user_input()          # all text Parts joined together
        task_id, context_id = context.task_id, context.context_id

        # 1) If this is a brand-new task, announce it (state = SUBMITTED)
        if context.current_task is None:
            await event_queue.enqueue_event(
                new_task(task_id, context_id, TaskState.TASK_STATE_SUBMITTED, history=[context.message])
            )

        updater = TaskUpdater(event_queue, task_id, context_id)

        # 2) Tell the client we are working (streaming clients see this live)
        await updater.start_work(
            new_text_message("Looking up threat intelligence...", context_id=context_id, task_id=task_id)
        )

        try:
            # 3) Run the LangGraph agent. thread_id = context_id gives it conversation memory.
            result = await self.graph.ainvoke(
                {"messages": [HumanMessage(content=user_text)]},
                config={"configurable": {"thread_id": context_id}},
            )
            answer = result["messages"][-1].content

            # 4) Publish the answer as an ARTIFACT, then mark the task COMPLETED
            await updater.add_artifact([new_text_part(answer)], name="threat_intel_report")
            await updater.complete()
        except Exception as exc:  # report failures through A2A instead of crashing
            log.exception("Threat-intel agent failed")
            await updater.failed(
                new_text_message(f"Threat-intel agent error: {exc}", context_id=context_id, task_id=task_id)
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.cancel()
