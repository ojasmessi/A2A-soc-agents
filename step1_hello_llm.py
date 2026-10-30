"""
STEP 1 — Prove your OpenAI key works with LangChain (the smallest possible program).

    python step1_hello_llm.py
"""

import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()  # reads OPENAI_API_KEY (and OPENAI_MODEL) from the .env file

llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-5-mini"))
reply = llm.invoke("In one sentence, what is a SOC analyst?")
print(reply.content)  # reply is an AIMessage; .content is the text
