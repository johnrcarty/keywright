"""Exercise real SSH transport pinning and streamed output limits against a disposable server."""
import asyncio
import shlex

import asyncssh
import pytest

from keywright_server import ssh


@pytest.mark.parametrize('source', ['1.2.3.4" command="id', "1.2.3.4'; id; '", '1.2.3.4\nexample'])
def test_authorized_key_source_rejects_injection(source):
    with pytest.raises(ValueError):
        ssh.authorized_keys_line('ssh-ed25519 AAAA test', source)


def test_enrollment_quotes_key_comment():
    script = ssh.enroll_script("ssh-ed25519 AAAA comment's $(id)", None)
    assert shlex.quote("ssh-ed25519 AAAA comment's $(id)") in script


class SSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


@pytest.fixture
async def ssh_server():
    host_key = asyncssh.generate_private_key('ssh-ed25519')
    commands = []
    async def handle(process):
        commands.append(process.command)
        if process.command == 'large':
            process.stdout.write(b'a' * (ssh.MAX_OUTPUT + 4096))
            process.stderr.write(b'b' * 65536)
        elif process.command == 'wait':
            await asyncio.sleep(2)
        else:
            process.stdout.write(b'keywright-ok\n')
        process.exit(0)
    server = await asyncssh.create_server(SSHServer, '127.0.0.1', 0, server_host_keys=[host_key],
                                         process_factory=handle, encoding=None)
    yield {'host': '127.0.0.1', 'port': server.get_port(), 'user': 'test',
           'host_key': host_key.export_public_key().decode()}, commands
    server.close()
    await server.wait_closed()


async def test_streamed_output_is_bounded(ssh_server):
    config, commands = ssh_server
    result = await ssh.run(config, 'large')
    assert result.exit_code == 0 and result.truncated
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= ssh.MAX_OUTPUT
    assert commands == ['large']


async def test_ssh_timeout_stops_waiting(ssh_server):
    config, _ = ssh_server
    result = await ssh.run(config, 'wait', timeout=1)
    assert result.exit_code == 124 and 'timed out' in result.stderr


async def test_wrong_host_pin_prevents_command(ssh_server):
    config, commands = ssh_server
    wrong = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    with pytest.raises(asyncssh.HostKeyNotVerifiable):
        await ssh.run({**config, 'host_key': wrong}, 'uptime')
    assert commands == []


async def test_password_enrollment_respects_existing_pin(ssh_server):
    config, commands = ssh_server
    wrong = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    ok, message, learned = await ssh.enroll_with_password(
        {**config, 'host_key': wrong}, 'test-password', 'ssh-ed25519 AAAA test')
    assert not ok and learned is None and 'HostKeyNotVerifiable' in message
    assert commands == []


async def test_no_ambient_agent_or_ssh_config(monkeypatch):
    captured = {}
    class Stopped(Exception):
        pass
    def connect(**kwargs):
        captured.update(kwargs)
        raise Stopped
    monkeypatch.setattr(asyncssh, 'connect', connect)
    with pytest.raises(Stopped):
        await ssh.run({'host': 'example.invalid'}, 'uptime')
    assert captured['client_keys'] == [] and captured['agent_path'] is None and captured['config'] is None
