"""Manual local-browser checks for the searchable device-type picker; never contacts a controller."""

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["KW_DATA_DIR"] = tempfile.mkdtemp(prefix="kw-kind-data-")
os.environ["KW_SECRET_KEY"] = "isolated-kind-fixture"
os.environ.pop("KW_DB_URL", None)
from starlette.requests import Request
from websockets.sync.client import connect

from keywright_server import db, discovery, inventory, reconciliation
from keywright_server.models import Resource
from keywright_server.web.admin import render
from keywright_server.web.inventory_ui import asset_context, context

out = Path(tempfile.mkdtemp(prefix="keywright-kind-ui-"))
request = Request(
    {
        "type": "http",
        "method": "GET",
        "path": "/ui/inventory/assets/new",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("fixture", 80),
    }
)


async def pages():
    await db.init_db()
    async with db.session() as s:
        source = Resource(name="Fixture controller", kind="mcp", config={"adapter": "omada"})
        s.add(source)
        await s.commit()
        rid = source.id
        a = await inventory.save_asset(s, {"name": "Saved vent", "kind": "smart_vent"})
        await s.commit()
        aid = a.id
    run_id, _ = await discovery.start_run(rid, "omada")
    await discovery.finish_run(
        run_id,
        [
            {
                "external_id": "client/vent",
                "data": {
                    "name": "Tapo-Vent",
                    "kind": "device",
                    "site": "Home",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "addresses": [],
                    "medium": "wifi",
                    "port": "Home Wi-Fi",
                    "attachment": "",
                    "parent": "",
                    "status": "Active",
                },
            }
        ],
    )
    async with db.session() as s:
        from sqlalchemy import select

        obs = await s.scalar(select(discovery.Observation))
        review = await reconciliation.review(s, obs.id)
    data = await context()
    for name, template, ctx in [
        ("new", "inventory_asset.html", asset_context(data, None)),
        ("edit", "inventory_asset.html", asset_context(data, data["asset_map"][aid])),
        ("review", "inventory_discovery_review.html", review),
    ]:
        (out / (name + ".html")).write_bytes(render(request, template, **ctx).body)
    await db.engine().dispose()


asyncio.run(pages())
profile = tempfile.mkdtemp(prefix="kw-kind-chrome-")
browser = subprocess.Popen(
    [
        os.environ.get(
            "CHROMIUM", str(Path.home() / ".cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
        ),
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-background-networking",
        "--remote-debugging-port=0",
        "--user-data-dir=" + profile,
        "about:blank",
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    active = Path(profile) / "DevToolsActivePort"
    for _ in range(100):
        if active.exists():
            break
        time.sleep(0.1)
    port = active.read_text().splitlines()[0]
    targets = json.load(urllib.request.urlopen("http://127.0.0.1:" + port + "/json"))
    with connect(targets[0]["webSocketDebuggerUrl"], max_size=30 * 1024 * 1024) as ws:
        seq = 0
        errors = []
        results = []

        def call(method, params=None):
            global seq
            seq += 1
            ws.send(json.dumps({"id": seq, "method": method, "params": params or {}}))
            while True:
                m = json.loads(ws.recv())
                if m.get("method") == "Runtime.exceptionThrown":
                    errors.append(m["params"])
                if m.get("id") == seq:
                    assert "error" not in m, m
                    return m.get("result", {})

        def ev(js):
            r = call("Runtime.evaluate", {"expression": js, "returnByValue": True, "awaitPromise": True})
            assert "exceptionDetails" not in r, r
            return r["result"].get("value")

        def screenshot(name):
            r = call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
            (out / (name + ".png")).write_bytes(base64.b64decode(r["data"]))

        def query(value):
            ev(
                "(()=>{const input=document.querySelector('[role=combobox]');input.value="
                + json.dumps(value)
                + ";input.dispatchEvent(new Event('input'));})()"
            )

        call("Page.enable")
        call("Runtime.enable")
        for width in (1280, 390):
            call(
                "Emulation.setDeviceMetricsOverride",
                {"width": width, "height": 850, "deviceScaleFactor": 1, "mobile": False},
            )
            call(
                "Emulation.setEmulatedMedia",
                {"features": [{"name": "prefers-color-scheme", "value": "dark"}]},
            )
            for page, initial in [("new", "physical"), ("edit", "smart_vent"), ("review", "device")]:
                call("Page.navigate", {"url": (out / (page + ".html")).as_uri()})
                time.sleep(0.15)
                assert ev("document.querySelector('[data-device-kind] select').value") == initial
                assert ev("document.documentElement.scrollWidth<=innerWidth")
                ev("document.querySelector('[data-device-kind]').scrollIntoView({block:'center'})")
                coords = ev(
                    "(()=>{const r=document.querySelector('[role=combobox]').getBoundingClientRect();return {x:r.x+25,y:r.y+20}})()"
                )
                call("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [coords]})
                call("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
                call("Input.insertText", {"text": "vent"})
                assert ev("document.querySelector('[role=combobox]').value") == "vent"
                assert ev("[...document.querySelectorAll('[role=option]')].map(n=>n.textContent)") == [
                    "Smart vent / HVAC damper"
                ]
                # Typing a partial match must not silently change the saved value or permit submission.
                assert ev("document.querySelector('[data-device-kind] select').value") == initial
                assert not ev("document.querySelector('[role=combobox]').checkValidity()")
                screenshot(page + "-" + str(width))
                coords = ev(
                    "(()=>{const r=document.querySelector('[role=option]').getBoundingClientRect();return {x:r.x+25,y:r.y+20}})()"
                )
                call("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [coords]})
                call("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
                assert ev("document.querySelector('[data-device-kind] select').value") == "smart_vent"
                assert (
                    ev("new FormData(document.querySelector('[data-device-kind] select').form).get('kind')")
                    == "smart_vent"
                )
                assert ev("document.querySelector('[role=combobox]').checkValidity()")
                query("sensor")
                assert ev("document.querySelectorAll('[role=option]').length") >= 8
                ev(
                    "document.querySelector('[role=combobox]').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown'}))"
                )
                expected = ev("document.querySelector('[role=option].active').textContent")
                ev(
                    "document.querySelector('[role=combobox]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}))"
                )
                assert ev("document.querySelector('[role=combobox]').value") == expected
                query("no such device kind")
                assert ev("document.querySelectorAll('[role=option]').length") == 0
                assert not ev("document.querySelector('[role=combobox]').checkValidity()")
                ev(
                    "document.querySelector('[role=combobox]').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))"
                )
                assert ev("document.querySelector('[role=combobox]').value") == expected
                assert ev("document.querySelector('[role=combobox]').checkValidity()")
                query("SMART PLUG")
                assert ev("document.querySelectorAll('[role=option]').length") == 1
                ev("document.querySelector('[role=option]').click()")
                assert (
                    ev("new FormData(document.querySelector('[data-device-kind] select').form).get('kind')")
                    == "smart_plug"
                )
                assert not errors, errors
                results.append(
                    {
                        "page": page,
                        "width": width,
                        "options": ev("document.querySelector('[data-device-kind] select').options.length"),
                    }
                )
        # Without JS, every category is still available through the native select.
        call("Emulation.setScriptExecutionDisabled", {"value": True})
        call("Page.navigate", {"url": (out / "review.html").as_uri()})
        time.sleep(0.1)
        call("Emulation.setScriptExecutionDisabled", {"value": False})
        assert ev("document.querySelector('[data-device-kind] select').getBoundingClientRect().height") > 0
        assert ev("document.querySelector('[data-device-kind] select').options.length") == len(
            inventory.KINDS
        )
        print(json.dumps({"checks": results, "javascript_errors": errors, "screenshots": str(out)}))
finally:
    browser.terminate()
    browser.wait(timeout=10)
