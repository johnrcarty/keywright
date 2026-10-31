import httpx
import pytest
from sqlalchemy import select

from keywright_server import ssh
from keywright_server.models import Resource


def test_generate_key_and_script(tmp_path):
    _, pub = ssh.generate_key("nvr", tmp_path / "keys")
    assert (tmp_path / "keys" / "nvr").stat().st_mode & 0o777 == 0o600
    assert pub.startswith("ssh-ed25519 ") and pub.endswith("keywright->nvr")
    with pytest.raises(FileExistsError):
        ssh.generate_key("nvr", tmp_path / "keys")
    script = ssh.enroll_script(pub, "10.0.0.2")
    assert 'from="10.0.0.2" ssh-ed25519' in script and "authorized_keys" in script and "chmod 600" in script
    assert 'from=' not in ssh.enroll_script(pub, None)


@pytest.fixture
async def ssh_res(db):
    r = Resource(kind="ssh", name="nvr", default_mode="approval", config={"host": "127.0.0.1", "user": "root", "port": 22})
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r


async def test_deleting_a_resource_frees_its_name_for_a_new_key(live_server, ssh_res, db, tmp_path):
    from keywright_server.config import settings

    own = tmp_path / "admin_key"
    own.write_text("mine")
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}, follow_redirects=True) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        await http.post(f"/ui/resources/{ssh_res.id}/keygen")
        assert (settings.keys_dir / "nvr").exists()
        page = await http.post(f"/ui/resources/{ssh_res.id}/delete")
        assert "with its key" in page.text
        assert not (settings.keys_dir / "nvr").exists() and not (settings.keys_dir / "nvr.pub").exists()
        # recreated under the same name (say, after a mistyped IP), it can be keyed again
        await http.post("/ui/resources", data={"kind": "ssh", "name": "nvr", "host": "127.0.0.2"})
        again = (await db.execute(select(Resource).where(Resource.name == "nvr"))).scalar_one()
        assert "Key generated" in (await http.post(f"/ui/resources/{again.id}/keygen")).text
        # a key the admin keeps elsewhere is not Keywright's to delete
        await http.post("/ui/resources", data={"kind": "ssh", "name": "cam", "host": "127.0.0.3", "key_path": str(own)})
        cam = (await db.execute(select(Resource).where(Resource.name == "cam"))).scalar_one()
        assert "with its key" not in (await http.post(f"/ui/resources/{cam.id}/delete")).text
        assert own.exists()
        await http.post(f"/ui/resources/{again.id}/delete")


async def test_ui_keygen_and_enroll_flow(live_server, ssh_res, monkeypatch):
    calls = {}

    async def fake_enroll(config, password, pub_line, restrict=True, *, login_user=None, escalate=None, root_password=None):
        calls.update(config=config, password=password, pub=pub_line, restrict=restrict, login_user=login_user,
                     escalate=escalate, root_password=root_password)
        return True, "keywright: key installed; key login verified", "ssh-ed25519 AAAAhostkey"

    monkeypatch.setattr(ssh, "enroll_with_password", fake_enroll)
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}, follow_redirects=True) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.get(f"/ui/resources/{ssh_res.id}")
        assert "Generate key on this Keywright" in page.text
        page = await http.post(f"/ui/resources/{ssh_res.id}/keygen")
        assert "Key generated" in page.text and f"/ui/resources/{ssh_res.id}/enroll" in page.text and "curl -fsSL" in page.text
        # the paste-able script endpoint works without login
        cmd = page.text.split("curl -fsSL ")[1].split(" | sh")[0]
        path = "/enroll/" + cmd.split("/enroll/")[1]
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as anon:
            script = await anon.get(path)
            assert script.status_code == 200 and "authorized_keys" in script.text and "ssh-ed25519" in script.text
            bad = await anon.get("/enroll/nope")
            assert bad.status_code == 404
        # password enrolment (mocked ssh) pins the host key
        page = await http.post(f"/ui/resources/{ssh_res.id}/enroll",
                               data={"password": "hunter2", "restrict": "1", "login_user": "john", "escalate": "su",
                                     "root_password": "rootpw"})
        assert "Enrolled:" in page.text and calls["password"] == "hunter2" and calls["restrict"] is True
        assert calls["login_user"] == "john" and calls["escalate"] == "su" and calls["root_password"] == "rootpw"
        assert calls["pub"].startswith("ssh-ed25519 ")
        assert "AAAAhostkey" in page.text  # pinned host key now shown
        audit = await http.get("/ui/audit")
        assert "ssh.enroll" in audit.text and "hunter2" not in audit.text and "rootpw" not in audit.text


async def test_enroll_escalation_commands(monkeypatch):
    """Drive enroll_with_password against a fake asyncssh connection to check the su/sudo command shapes."""
    import asyncssh

    runs = []

    class FakeResult:
        exit_status, stdout, stderr = 0, "Password: \r\nkeywright: key installed for root@box\r\n", ""

    class FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get_extra_info(self, k):
            return {"sockname": ("10.0.0.2", 5555)}[k]

        def get_server_host_key(self):
            return None

        async def run(self, cmd, **kw):
            runs.append((cmd, kw))
            return FakeResult()

    def fake_connect(*a, **kw):
        runs.append(("connect", kw))
        return FakeConn()

    async def fake_probe(config):
        return True, "ok", None

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    monkeypatch.setattr(ssh, "probe", fake_probe)
    cfg = {"host": "box", "user": "root"}

    ok, msg, _ = await ssh.enroll_with_password(cfg, "pw", "ssh-ed25519 AAAA x", login_user="john", escalate="su",
                                                root_password="rootpw")
    assert ok and "key installed" in msg
    assert runs[0][1]["username"] == "john" and runs[0][1]["password"] == "pw"
    cmd, kw = runs[1]
    assert cmd.startswith("su - root -c ") and "base64 -d | sh" in cmd and kw["input"] == "rootpw\n" and kw["term_type"]

    runs.clear()
    ok, msg, _ = await ssh.enroll_with_password(cfg, "pw", "ssh-ed25519 AAAA x", login_user="john", escalate="sudo")
    cmd, kw = runs[1]
    assert ok and cmd.startswith("sudo -H -S -p '' -u root sh -c ") and kw["input"] == "pw\n"

    runs.clear()
    ok, msg, _ = await ssh.enroll_with_password(cfg, "pw", "ssh-ed25519 AAAA x", login_user="john")
    assert not ok and "no escalation" in msg

    runs.clear()
    ok, _, _ = await ssh.enroll_with_password(cfg, "pw", "ssh-ed25519 AAAA x")
    assert ok and runs[1][0].startswith("set -e") and 'from="10.0.0.2"' in runs[1][0]


async def test_startup_points_a_moved_key_path_at_this_instances_keys_dir(db):
    """Resources from before the rename store /var/lib/gatekeeper/keys/<name>; a container or a
    new host has the same file under the current keys dir and nothing at the old path."""
    from sqlalchemy import text

    from keywright_server.config import settings
    from keywright_server.db import _relocate_key_paths, engine

    settings.ensure_dirs()
    (settings.keys_dir / "pve").write_text("k")
    own = settings.data_dir / "elsewhere"
    own.write_text("k")
    db.add_all([
        Resource(kind="ssh", name="pve", config={"host": "h", "key_path": "/var/lib/gatekeeper/keys/pve"}),
        Resource(kind="ssh", name="gone", config={"host": "h", "key_path": "/var/lib/gatekeeper/keys/gone"}),
        Resource(kind="ssh", name="own", config={"host": "h", "key_path": str(own)}),
    ])
    await db.commit()
    async with engine().begin() as conn:
        await conn.run_sync(_relocate_key_paths)
    async with engine().connect() as conn:
        rows = dict((await conn.execute(text("SELECT name, config FROM resources"))).fetchall())
    import json
    paths = {n: json.loads(c)["key_path"] for n, c in rows.items()}
    assert paths["pve"] == str(settings.keys_dir / "pve")
    assert paths["gone"] == "/var/lib/gatekeeper/keys/gone"  # no such key here: left alone, the UI shows it missing
    assert paths["own"] == str(own)
