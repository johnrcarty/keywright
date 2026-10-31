from __future__ import annotations

import argparse
import asyncio
import secrets
import sys


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="keywright-server", description="Keywright server: JIT credential broker for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the server")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    a = sub.add_parser("create-agent", help="create an agent and print its token once")
    a.add_argument("name")
    sub.add_parser("set-admin-password", help="set/reset the admin UI password (prompts)")
    args = p.parse_args(argv)

    from .config import settings

    if args.cmd == "serve":
        import uvicorn

        from .web.app import create_app

        uvicorn.run(create_app(), host=args.host or settings.host, port=args.port or settings.port, log_level="info",
                    forwarded_allow_ips=settings.trusted_proxies or None)
        return 0
    if args.cmd == "create-agent":
        return asyncio.run(_create_agent(args.name))
    if args.cmd == "set-admin-password":
        import getpass

        pw = getpass.getpass("New admin password: ")
        if pw != getpass.getpass("Repeat: "):
            print("passwords differ", file=sys.stderr)
            return 1
        return asyncio.run(_set_password(pw))
    return 1


async def _create_agent(name: str) -> int:
    from .db import init_db, session
    from .mcp_server import hash_token
    from .models import Agent

    await init_db()
    token = "kw_" + secrets.token_urlsafe(32)
    async with session() as db:
        db.add(Agent(name=name, token_hash=hash_token(token), token_prefix=token[:8]))
        await db.commit()
    print(token)
    return 0


async def _set_password(pw: str) -> int:
    from .db import init_db, session
    from .settings_store import warm
    from .web.auth import set_password

    await init_db()
    async with session() as db:
        await warm(db)
        await set_password(db, pw)
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
