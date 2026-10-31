"""keywright-router run|check|dry-run [--config PATH]

  run       poll forever (the container's command)
  check     validate the rules file and exit
  access    print the standing access the rules need (as Keywright qualifies the calls) and ask
            for what is missing in one request; approve it with Always allow
  dry-run   one pass over today's unread mail: route each message and print the calls it would
            make, without making them or recording anything. Reads and labels still go through
            Keywright, so they are audited like any other call.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .config import ConfigError, load


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="keywright-router", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "check", "access", "dry-run"])
    ap.add_argument("--config", default="/config/rules.yaml")
    ap.add_argument("--log-level", default="INFO")
    a = ap.parse_args(argv)
    logging.basicConfig(level=a.log_level.upper(), format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = load(a.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if a.command == "check":
        print(f"ok: {len(cfg.rules)} rules, {len(cfg.unmatched)} unmatched actions, "
              f"llm {'used (' + str(cfg.model) + ')' if cfg.uses_llm else 'not used'}")
        return 0

    from .router import Router
    if a.command == "access":
        return asyncio.run(_access(cfg))
    if a.command == "run":
        asyncio.run(Router(cfg).run_forever())
        return 0
    return asyncio.run(_dry_run(cfg))


async def _access(cfg) -> int:
    from . import access
    from .kw import Keywright

    status, rid, patterns = await access.ensure(Keywright(cfg.kw_url, cfg.kw_token, cfg.session), cfg)
    for p in patterns:
        print(p)
    print(f"{status}{' ' + rid if rid else ''}", file=sys.stderr)
    return 0 if status in ("approved", "pending") else 1


async def _dry_run(cfg) -> int:
    from .kw import Pending
    from .router import Router

    router = Router(cfg)
    for meta in await router.unread():
        msg = await router.fetch(str(meta["email_id"]))
        if msg is None:
            continue
        try:
            job = await router.plan(msg)
        except Pending as p:
            print(f"{msg.key}: needs approval first ({p.request_id})")
            continue
        seen = " (already handled)" if router.store.has(msg.key) else ""
        print(f"\n{msg.key}{seen}  {msg.subject!r} from {msg.sender_address}")
        for s in job.steps:
            print("  ", json.dumps({k: v for k, v in s.items() if k != "reason"})[:400])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
