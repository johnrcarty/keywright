"""Keywright router: watches a mailbox through Keywright and acts on what arrives.

The router is an ordinary Keywright agent. It holds no mail password and no provider key:
it reads and sends mail through the brokered `email` MCP server, asks the LLM gateway only
when a rule needs a label or a draft, and every call it makes is checked against the rules
the human set for its token. Routing itself is plain boolean logic over the message.
"""

__version__ = "0.0.2"
