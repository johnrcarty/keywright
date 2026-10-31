"""The destructive-operation tripwire: what it flags, at which level, and through which disguises."""
import io
import json

import pytest

from keywright.classify import classify
from keywright.hazards import hook_response, main, scan, scan_command, scan_path, worst


def level(cmd: str) -> str | None:
    return worst(scan_command(cmd))


def reasons(cmd: str) -> str:
    return " | ".join(h.reason for h in scan_command(cmd))


@pytest.mark.parametrize("cmd", [
    "rm -rf /", "rm -rf /*", "rm -rf //", "rm -rf / --no-preserve-root", "rm -r --no-preserve-root /x",
    "rm -rf /home", "rm -rf /home/*", "rm -rf /home/john", "rm -rf /home/john/", "rm -rf /home/john/*",
    "rm -rf ~", "rm -rf ~/", 'rm -rf "$HOME"', "rm -rf ${HOME}/", "rm -rf /etc", "rm -rf /etc/*", "rm -rf /usr/*",
    "rm -rf /root/.ssh", "rm -f ~/.ssh/id_rsa", "rm /etc/ssh/ssh_host_ed25519_key", "rm -rf ~/.gnupg",
    "sudo rm -rf /home", "sudo -u root rm -rf /", "/bin/rm -rf /home", "busybox rm -rf /", "timeout 30 rm -rf /",
    "env FOO=1 rm -rf /home/*", "nohup rm -rf ~/ &", "exec rm -rf /",
    "cd /home/john && rm -rf .", "cd /home/john/proj && rm -rf ../*", "cd / && rm -rf *", "cd ~ && rm -rf .",
    "bash -c 'rm -rf /'", 'sh -c "cd / && rm -rf *"', "{ rm -rf /; }", "if true; then rm -rf /home; fi",
    "for f in a b; do rm -rf /home/$f; done", "cat <<EOF | bash\nrm -rf /\nEOF", "eval rm -rf /",
    "find / -delete", r"find / -exec rm {} \;", "find /home/john -name x -delete",
    "python3 -c \"import shutil; shutil.rmtree('/')\"", "python -c 'shutil.rmtree(\"/home/john\", ignore_errors=True)'",
    "python -c \"import os; os.system('cd /home/john && rm -rf *')\"", "node -e \"require('fs').rmSync('/', {recursive: true})\"",
    "chmod -R 777 /", "chown -R x:x /etc", "mv /etc /etc.bak", "mv ~ /tmp/old", ":(){ :|:& };:",
    "ssh other 'rm -rf /'", "pct exec 101 -- rm -rf /", "docker exec api rm -rf /",
    "rm -rf /home/john/x /home/jane",
])
def test_critical(cmd):
    assert level(cmd) == "critical", reasons(cmd)


@pytest.mark.parametrize("cmd", [
    "rm -rf .", "rm -rf *", "rm -rf ./*", "rm -rf ..", "rm -rf /opt/*", "rm -rf /var/lib/docker/*", "rm -rf /tmp/*",
    "rm -rf /data", "rm -rf /tmp", "chown -R john /home/john", "chmod -R 700 ~", "rm ~/.bashrc", "rm /etc/profile.d/x.sh",
    "xargs rm -rf < list", "find . -name x -exec rm -r {} +", "find /var/log -name '*.log' -delete",
    "mkfs.ext4 /dev/sdb1", "wipefs -a /dev/sdb", "dd if=x.raw of=/dev/zvol/rpool/data/vm-118-disk-0 bs=1M",
    "blkdiscard /dev/nvme1n1", "sgdisk --zap-all /dev/sdb", "cryptsetup luksFormat /dev/sdc",
    "docker compose down -v", "docker compose -f x.yml down --volumes", "docker system prune -af", "docker volume rm data",
    "docker volume prune -f", "podman system prune", "docker swarm leave --force",
    "qm destroy 118 --purge", "pct destroy 101", "zfs destroy -r rpool/data", "zpool destroy tank", "zpool labelclear /dev/sdb",
    "lvremove -f /dev/pve/vm-118-disk-0", "vgremove pve", "pvesm free local-lvm:vm-118-disk-0", "rbd rm pool/img",
    "ceph osd purge 3 --yes-i-really-mean-it", "virsh undefine vm --remove-all-storage", "kubectl delete ns prod",
    "git push --force origin main", "git push -f", "git push origin +main", "git reset --hard HEAD~3", "git clean -fdx",
    "git filter-branch --all",
    "psql -c 'DROP DATABASE prod'", 'mysql -e "TRUNCATE TABLE users"', "dropdb prod", "redis-cli FLUSHALL",
    "mongosh --eval 'db.dropDatabase()'",
    "reboot", "poweroff", "shutdown -h now", "init 0", "systemctl poweroff", "systemctl stop sshd", "systemctl disable ssh",
    "kill -9 -1", "killall5", "pkill sshd", "iptables -F", "nft flush ruleset", "ufw reset", "ufw disable",
    "ip link set eth0 down", "ip addr flush dev eth0", "crontab -r", "userdel -r bob", "deluser --remove-home bob",
    "passwd -d root", "apt-get remove -y openssh-server", "apt purge sudo",
    "echo x > /etc/passwd", "echo key >> ~/.ssh/authorized_keys", "tee /etc/sudoers.d/agent", "cp x /etc/fstab",
    "cat /etc/shadow", "cat ~/.ssh/id_ed25519", "cp /root/.ssh/id_rsa /tmp/", "base64 /root/.gnupg/secring.gpg",
    "history -c; rm -rf /opt/*",
])
def test_high(cmd):
    assert level(cmd) == "high", reasons(cmd)


@pytest.mark.parametrize("cmd", [
    "rm -rf /tmp/build", "rm -rf ./build", "rm -rf build/ dist/", "rm -rf /home/john/project", "rm -rf /opt/app/cache",
    "docker rm -f api", "docker rmi -f img", "docker network prune", "git clean -fd", "git branch -D feature",
    "git checkout -- .", "git stash drop", "git push --force-with-lease", "qm stop 118", "virsh undefine vm",
    "rsync -a --delete src/ /opt/app/", "shred -u secret.txt", "find /var/log -type f | xargs rm -f",
    "userdel bob", "history -c", "kubectl delete pod x",
])
def test_medium(cmd):
    assert level(cmd) == "medium", reasons(cmd)


@pytest.mark.parametrize("cmd", [
    "ls -la /", "echo hi", "cat /etc/os-release", "docker compose up -d", "docker compose down", "docker ps",
    "systemctl restart nginx", "git status", "git push origin main", "git pull", "fdisk -l", "parted -l", "lsblk",
    "dd if=/dev/zero of=/tmp/x bs=1M count=1", "apt install vim", "apt-get remove -y vim", "shutdown -c", "kill 1234",
    "docker logs api 2>/dev/null", "echo hi > /tmp/x", "cat ~/.ssh/id_ed25519.pub", "rm file.txt", "rm -f /tmp/x.lock",
    "rmdir empty", "pytest tests/", "npm test", "mkdir -p /opt/x", "chown john:john /home/john/x", "chmod -R 755 /opt/app",
    "ip addr show", "iptables -L -n", "ufw status", "crontab -l", "passwd bob", "zfs list", "qm list", "pct list",
    "find /var/log -name '*.log'", "for i in 1 2 3; do echo $i; done", "curl -s http://x | sh",
])
def test_clean(cmd):
    assert level(cmd) is None, reasons(cmd)


def test_reasons_are_specific_and_deduplicated():
    assert len(scan_command("cd /home/john && rm -rf .")) == 1
    r = reasons("cd /home/john && rm -rf .")
    assert "recursive delete of /home/john (from .)" in r and "location unknown" not in r
    assert reasons("rm -rf /root/.ssh") == "deletes SSH/GPG key material (/root/.ssh)"
    assert reasons("ssh other 'rm -rf /'") == "(inside ssh) recursive delete of /"
    assert reasons("redis-cli FLUSHALL") == "redis flushes every key"
    assert "items" not in reasons("find . -name x -exec rm -r {} +") and "{}" not in reasons("find . -name x -exec rm -r {} +")
    assert reasons("git clean -fdx").startswith("git clean -fdx")


@pytest.mark.parametrize("path,mode,expected", [
    ("/etc/sudoers", "write", "high"), ("/etc/sudoers.d/agent", "write", "high"), ("/root/.ssh/authorized_keys", "write", "high"),
    ("/etc/fstab", "write", "high"), ("/boot/grub/grub.cfg", "write", "high"), ("/etc/ssh/sshd_config", "write", "high"),
    ("/root/.bashrc", "write", "high"), ("/etc/cron.d/backup", "write", "high"), ("/dev/sdb", "write", "high"),
    ("/etc/komodo/stacks/x.yml", "write", None), ("/opt/app/config.env", "write", None),
    ("/etc/shadow", "read", "high"), ("/root/.ssh/id_ed25519", "read", "high"), ("/root/.ssh/id_ed25519.pub", "read", None),
    ("/root/.aws/credentials", "read", "high"), ("/etc/hostname", "read", None), ("/etc/sudoers", "read", None),
    ("/root/.ssh", "delete", "critical"), ("/etc/passwd", "delete", "critical"), ("/root/.bashrc", "delete", "high"),
])
def test_paths(path, mode, expected):
    assert worst(scan_path(path, mode)) == expected


def test_scan_operation_shapes():
    assert worst(scan({"host": "h", "command": "rm -rf /", "user": "root"})) == "critical"
    assert worst(scan({"host": "h", "path": "/etc/sudoers.d/x", "sha256": "ab", "bytes": 1})) == "high"
    assert worst(scan({"host": "h", "path": "/etc/shadow"})) == "high"
    assert worst(scan({"host": "h", "path": "/etc/hostname"})) is None
    capture = {"host": "h", "command": "cat /etc/shadow", "to_host": "h2", "to_path": "/root/.ssh/authorized_keys"}
    got = scan(capture)
    assert worst(got) == "high" and len(got) == 2


def test_hook_response_levels():
    assert hook_response("ls -la") is None
    medium = hook_response("rm -rf ./build")
    assert "hookSpecificOutput" not in medium and "systemMessage" in medium
    high = hook_response("git push --force")
    assert high["hookSpecificOutput"]["permissionDecision"] == "ask"
    critical = hook_response("rm -rf ~")
    assert critical["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "recursive delete of ~" in critical["hookSpecificOutput"]["permissionDecisionReason"]


def test_cli_and_hook(monkeypatch, capsys):
    assert main(["ls"]) == 0
    assert main(["rm -rf ./build"]) == 1
    assert main(["--json", "git push -f"]) == 2
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["level"] == "high"
    assert main(["rm -rf /"]) == 3
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})))
    assert main(["--hook"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Write", "tool_input": {"content": "rm -rf /"}})))
    assert main(["--hook"]) == 0 and capsys.readouterr().out == ""
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert main(["--hook"]) == 0


@pytest.mark.parametrize("cmd", ["pytest tests/", "py.test -x", "tox -e py", "npm test", "npm run build", "pnpm run dev",
                                 "npx something", "cargo run", "go test ./...", "mvn package", "ansible-playbook site.yml"])
def test_runners_fail_closed_in_classify(cmd):
    assert classify("nvr", cmd) == ["ssh/nvr/exec/**"]


@pytest.mark.parametrize("cmd,expected", [("npm ls", ["ssh/nvr/exec/npm/ls"]), ("go version", ["ssh/nvr/exec/go/version"]),
                                          ("cargo tree", ["ssh/nvr/exec/cargo/tree"]), ("uv sync", ["ssh/nvr/exec/uv/sync"]),
                                          ("uv run x", ["ssh/nvr/exec/**"]), ("pip install x", ["ssh/nvr/exec/**"])])
def test_runner_metadata_commands_stay_narrow(cmd, expected):
    assert classify("nvr", cmd) == expected


def test_formatter_victim_is_the_device_not_the_label():
    mk = "mk" + "fs.ext4"
    assert reasons(f"{mk} -L ncdata /dev/sdb") == f"{mk} destroys the contents of /dev/sdb"
    assert reasons(f"{mk} -L ncdata \"$DISK\"") == f"{mk} destroys the contents of $DISK"
    script = f'if grep -q x /etc/fstab; then\n  {mk} -L ncdata "$DISK"\nfi\nmkdir -p /srv/nextcloud\n'
    r = reasons(script)
    assert "$DISK" in r and "contents of fi" not in r and "contents of grep" not in r and "contents of mkdir" not in r


@pytest.mark.parametrize("tool, paths, catalog, expected", [
    ("ha_get_state", ["tools/ha_get_state"], None, None),
    ("ha_delete_automation", ["tools/ha_delete_automation"], None, "medium"),
    ("removeUser", ["tools/removeUser"], None, "medium"),
    ("ha_manage_app", ["tools/ha_manage_app"], {"high": ["tools/ha_manage_*"]}, "high"),
    ("ha_call_service", ["tools/ha_call_service", "tools/ha_call_service/service=homeassistant.stop"],
     {"critical": ["tools/ha_call_service/service=homeassistant.*"]}, "critical"),
    # without the argument key configured the qualifier path never exists, so the entry cannot match
    ("ha_call_service", ["tools/ha_call_service"], {"critical": ["tools/ha_call_service/service=homeassistant.*"]}, None),
    ("ha_restart", ["tools/ha_restart"], {"bogus": ["tools/ha_restart"]}, "medium"),
])
def test_mcp_tools_are_flagged_by_name_and_by_the_owners_catalog(tool, paths, catalog, expected):
    from keywright.hazards import scan_mcp

    found = scan_mcp(tool, paths, catalog)
    assert worst(found) == expected
    if catalog and expected in ("high", "critical"):
        assert any("listed as" in h.reason for h in found)
