"""Manual browser acceptance checks. No controller calls or production writes.

Run with the project's Python environment and a local Chromium binary. Optional --actual
accepts a private saved /ui/inventory/map/data response; it is never checked into the repo.
"""

import argparse
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
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--actual", type=Path)
parser.add_argument(
    "--chromium",
    default=os.environ.get(
        "CHROMIUM", str(Path.home() / ".cache/ms-playwright/chromium-1228/chrome-linux64/chrome")
    ),
)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
os.environ["KW_DATA_DIR"] = tempfile.mkdtemp(prefix="kw-layout-ui-")
os.environ["KW_SECRET_KEY"] = "isolated-ui-fixture"
from starlette.requests import Request
from websockets.sync.client import connect

from keywright_server.web.admin import render

out = args.output or Path(tempfile.mkdtemp(prefix="keywright-topology-ui-"))
out.mkdir(exist_ok=True, mode=0o700)
request = Request(
    {
        "type": "http",
        "method": "GET",
        "path": "/ui/inventory/map",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("fixture", 80),
    }
)
graphs = {
    str(n): json.loads(subprocess.check_output(["node", str(ROOT / "tests/topology_fixture.cjs"), str(n)]))
    for n in (25, 88, 160)
}
if args.actual:
    graphs["actual"] = json.loads(args.actual.read_text())
for name, graph in graphs.items():
    (out / (name + ".html")).write_bytes(render(request, "inventory_map.html", graph=graph).body)
profile = tempfile.mkdtemp(prefix="kw-layout-chrome-")
browser = subprocess.Popen(
    [
        args.chromium,
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

        def click(id):
            ev("document.getElementById(" + json.dumps(id) + ").click()")

        def screenshot(name):
            image = call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
            (out / (name + ".png")).write_bytes(base64.b64decode(image["data"]))

        call("Page.enable")
        call("Runtime.enable")
        call(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """window.__calls=0;window.__fail=false;window.__tick=null;window.__hidden=false;
Object.defineProperty(document,'hidden',{get:()=>window.__hidden});window.setInterval=fn=>{window.__tick=fn;return 1;};
window.fetch=async(url,options)=>{window.__calls++;if(window.__cooldown&&options?.method==='POST')return {ok:false,status:409,redirected:false,headers:new Headers({'content-type':'application/json'}),json:async()=>({error:'Recently refreshed'})};if(window.__fail)throw new Error('Controller unavailable');const graph=JSON.parse(document.getElementById('net-data').textContent);graph.last_success=graph.generated_at=new Date().toISOString();graph.fresh=true;if(window.__mutate)window.__mutate(graph);return {ok:true,redirected:false,headers:new Headers({'content-type':'application/json'}),json:async()=>graph};};"""
            },
        )
        results = []
        for name, graph in graphs.items():
            for width in (1280, 390):
                call(
                    "Emulation.setDeviceMetricsOverride",
                    {"width": width, "height": 1000, "deviceScaleFactor": 1, "mobile": False},
                )
                call(
                    "Emulation.setEmulatedMedia",
                    {
                        "features": [
                            {"name": "prefers-color-scheme", "value": "dark"},
                            {"name": "prefers-reduced-motion", "value": "reduce"},
                        ]
                    },
                )
                call("Page.navigate", {"url": (out / (name + ".html")).as_uri()})
                time.sleep(0.3)
                assert not errors, errors
                ev("document.querySelector('.net-workspace').scrollIntoView({block:'start'})")
                initial = ev(
                    """(()=>{const svg=document.getElementById('network-svg').getBoundingClientRect();return {width:innerWidth,scroll:document.documentElement.scrollWidth,nodes:document.querySelectorAll('.topo-node').length,hubs:document.querySelectorAll('.topo-node.hub').length,scale:document.getElementById('net-scale').textContent,outside:[...document.querySelectorAll('.topo-node.hub')].filter(n=>{const r=n.getBoundingClientRect();return r.left<svg.left-1||r.right>svg.right+1||r.top<svg.top-1||r.bottom>svg.bottom+1}).length,rows:document.querySelectorAll('#net-list tr').length}})()"""
                )
                assert initial["scroll"] <= width, initial
                assert initial["rows"] == len(graph["nodes"]), initial
                if width == 390:
                    assert initial["nodes"] == 7 and initial["outside"] == 0, initial
                screenshot(name + "-overview-" + str(width))
                # Choose the busiest hub. Keyboard selection expands a readable client page.
                parents = {
                    n["id"]: sum(c.get("attachment") == n["id"] for c in graph["nodes"] if not c["hub"])
                    for n in graph["nodes"]
                    if n["hub"]
                }
                parent = max(parents, key=parents.get)
                ev(
                    "document.querySelector("
                    + json.dumps('.topo-node[data-id="' + parent + '"]')
                    + ').dispatchEvent(new KeyboardEvent("keydown",{key:"Enter",bubbles:true}))'
                )
                expanded = ev(
                    """({clients:document.querySelectorAll('.topo-node.client').length,page:document.getElementById('net-page').textContent,scale:parseInt(document.getElementById('net-scale').textContent),path:document.querySelectorAll('.topo-edge.on-path').length,dim:document.querySelectorAll('.topo-node.dimmed').length})"""
                )
                assert expanded["clients"] >= min(parents[parent], 8 if width == 390 else 10), expanded
                assert expanded["scale"] >= 100 and expanded["path"] > 0 and expanded["dim"] > 0, expanded
                if width == 390:
                    screenshot(name + "-branch-" + str(width))
                # All SVG cards have disjoint bounding boxes, including expanded branches.
                collisions = ev(
                    """(()=>{const ns=[...document.querySelectorAll('.topo-node')].map(n=>({id:n.dataset.id,r:n.getBoundingClientRect()})),bad=[];for(let i=0;i<ns.length;i++)for(let j=i+1;j<ns.length;j++){const a=ns[i].r,b=ns[j].r;if(a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top)bad.push([ns[i].id,ns[j].id]);}return bad})()"""
                )
                assert not collisions, collisions
                # Status highlighting preserves coordinates and camera, and review dots stay independent.
                before = ev(
                    "document.getElementById('net-scene').getAttribute('transform')+'|'+[...document.querySelectorAll('.topo-node')].map(n=>n.getAttribute('transform')).join('|')"
                )
                ev("document.querySelector('[data-status=unreviewed]').click()")
                assert (
                    ev(
                        "document.getElementById('net-scene').getAttribute('transform')+'|'+[...document.querySelectorAll('.topo-node')].map(n=>n.getAttribute('transform')).join('|')"
                    )
                    == before
                )
                ev("document.querySelector('[data-status=\"\"]').click()")
                if parents[parent] > (8 if width == 390 else 10):
                    page1 = ev("document.getElementById('net-page').textContent")
                    click("net-next")
                    assert ev("document.getElementById('net-page').textContent") != page1
                click("net-collapse")
                assert ev("document.getElementById('net-collapse').textContent") == "Expand clients"
                click("net-collapse")
                # Search targets a client on the last page, expands that page, and opens details.
                client = max(
                    (n for n in graph["nodes"] if n.get("attachment") == parent and not n["hub"]),
                    key=lambda n: n["id"],
                )
                ev(
                    "(()=>{const q=document.getElementById('net-search');q.value="
                    + json.dumps(client["mac"])
                    + ";q.dispatchEvent(new Event('input'));q.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}));})()"
                )
                detail = ev(
                    "({title:document.getElementById('net-detail-title').textContent,hidden:document.getElementById('net-details').hidden,selected:document.querySelector('.topo-node.selected')?.dataset.id})"
                )
                assert detail == {"title": client["name"], "hidden": False, "selected": client["id"]}, detail
                if width == 390:
                    assert ev(
                        "document.getElementById('net-details').getBoundingClientRect().bottom<=document.querySelector('.mobile-nav').getBoundingClientRect().top+2"
                    )
                    screenshot(name + "-detail-" + str(width))
                click("net-detail-close")
                ev(
                    "document.getElementById('net-search').value='';document.getElementById('net-search').dispatchEvent(new Event('input'))"
                )
                # Refresh only updates status/metadata: no layout or camera jump.
                before = ev(
                    "document.getElementById('net-scene').outerHTML.match(/transform=\"[^\"]+\"/g).join('|')"
                )
                click("net-refresh")
                time.sleep(0.1)
                assert (
                    ev(
                        "document.getElementById('net-scene').outerHTML.match(/transform=\"[^\"]+\"/g).join('|')"
                    )
                    == before
                )
                click("net-overview")
                assert ev("document.querySelectorAll('.topo-node.client').length") == 0
                # Actual pointer touch tap on a hub, then pinch and pan (CDP touch events).
                ev("document.querySelector('.net-workspace').scrollIntoView({block:'start'})")
                coords = ev(
                    """(()=>{const r=document.querySelector('.topo-node.hub').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()"""
                )
                call("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [coords]})
                call("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
                assert ev("document.querySelectorAll('.topo-node.selected').length") == 1
                click("net-overview")
                r = ev(
                    "(()=>{const r=document.getElementById('network-svg').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+160}})()"
                )
                a = {"x": r["x"] - 40, "y": r["y"], "id": 1}
                b = {"x": r["x"] + 40, "y": r["y"], "id": 2}
                before = ev("document.getElementById('net-scale').textContent")
                call("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [a, b]})
                call(
                    "Input.dispatchTouchEvent",
                    {"type": "touchMove", "touchPoints": [{**a, "x": a["x"] - 30}, {**b, "x": b["x"] + 30}]},
                )
                call("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
                assert ev("document.getElementById('net-scale').textContent") != before
                before = ev("document.getElementById('net-scene').getAttribute('transform')")
                call("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [a]})
                call(
                    "Input.dispatchTouchEvent",
                    {"type": "touchMove", "touchPoints": [{**a, "y": a["y"] + 50}]},
                )
                call("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
                assert ev("document.getElementById('net-scene').getAttribute('transform')") != before
                results.append({"graph": name, **initial, "expanded": expanded})
        # Staleness, refresh failure, cooldown, and visibility remain faithful to the old behavior.
        ev("window.__cooldown=true")
        click("net-refresh")
        time.sleep(0.1)
        assert ev("document.getElementById('net-error').textContent") == "Recently refreshed"
        ev(
            "window.__cooldown=false;window.__hidden=true;window.__oldNow=Date.now;Date.now=()=>window.__oldNow()+190000;window.__tick()"
        )
        assert ev("document.querySelectorAll('.topo-node.online').length") == 0
        calls = ev("window.__calls")
        ev("window.__hidden=false;window.__fail=true;window.__tick()")
        time.sleep(0.1)
        assert ev("window.__calls") == calls + 1
        assert ev("document.getElementById('net-error').textContent") == "Controller unavailable"
        assert not errors, errors
        # Compact and light layouts; unknown connections and empty data never manufacture links.
        for case, width, theme in [
            ("compact", 320, "dark"),
            ("light", 1280, "light"),
            ("unknown", 390, "dark"),
            ("empty", 390, "dark"),
            ("no-source", 390, "dark"),
        ]:
            graph = json.loads(json.dumps(graphs["25"]))
            if case == "unknown":
                client = next(n for n in graph["nodes"] if not n["hub"])
                graph["edges"] = [e for e in graph["edges"] if e["target"] != client["id"]]
                client["attachment"] = ""
                client["attachment_label"] = ""
            if case in ("empty", "no-source"):
                graph["nodes"] = []
                graph["edges"] = []
            if case == "no-source":
                graph["sources"] = []
                graph["source"] = ""
            page = out / (case + ".html")
            page.write_bytes(render(request, "inventory_map.html", graph=graph).body)
            call(
                "Emulation.setDeviceMetricsOverride",
                {"width": width, "height": 1000, "deviceScaleFactor": 1, "mobile": False},
            )
            call(
                "Emulation.setEmulatedMedia",
                {
                    "features": [
                        {"name": "prefers-color-scheme", "value": theme},
                        {"name": "prefers-reduced-motion", "value": "reduce"},
                    ]
                },
            )
            call("Page.navigate", {"url": page.as_uri()})
            time.sleep(0.2)
            assert ev("document.documentElement.scrollWidth<=innerWidth")
            if case == "unknown":
                assert ev("document.querySelectorAll('.topo-node.unplaced').length") == 1
                ev(
                    "document.querySelector('.topo-node.unplaced').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))"
                )
                assert ev("document.querySelectorAll('.topo-edge').length") == 6
            elif case == "empty":
                assert not ev("document.getElementById('net-map-empty').hidden")
            elif case == "no-source":
                assert ev("document.getElementById('net-freshness').textContent") == "No controller connected"
            else:
                ev("document.querySelector('.net-workspace').scrollIntoView({block:'start'})")
            screenshot(case)
        assert not errors, errors
        print(json.dumps({"checks": results, "javascript_errors": errors, "screenshots": str(out)}))
finally:
    browser.terminate()
    browser.wait(timeout=10)
