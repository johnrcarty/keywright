"""Private MCP worker. Its stdout is a JSON-lines pipe owned by transport.acall."""

import asyncio
import json
import sys

from .config import Profile
from .transport import NETWORK_HINT, AuthError, TransportError, _call


def emit(kind, data):
    print(json.dumps([kind, data]), flush=True)


def main():
    try:
        request = json.load(sys.stdin)
        asyncio.run(_call(Profile(**request["profile"]), request["session"], request["tool"],
                          request["arguments"], request["read_timeout"], emit))
    except AuthError as e:
        emit("auth", str(e))
    except TransportError as e:
        emit("error", str(e))
    except Exception as e:  # noqa: BLE001 - never leak raw exceptions across the worker boundary
        emit("error", f"{type(e).__name__}; {NETWORK_HINT}")


if __name__ == "__main__":
    main()
