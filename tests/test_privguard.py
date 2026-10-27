"""Tests for privguard: privilege workarounds after a permission error.

Pure string tests; nothing is executed.
"""

from __future__ import annotations

import json

import pytest

from byebyeing.privguard import ECHO_NOTICE, NOTICE, repair_history, rewrite_call, workaround_hits

S = "su" + "do"  # written in two parts so the file reads as test data

POS = [f"{S} apt-get install -y pandoc", f"cd x && {S} mount -t tmpfs t /mnt", "su -c 'id'", "doas ls", "pkexec ls",
       "unshare -r id", "nsenter -t 1 -m", "chroot /x /bin/sh", "docker run --privileged img",
       "docker run -v /:/host img", "setcap cap_net_bind_service=+ep /usr/bin/python3", "chmod u+s ./x",
       "chmod 4755 ./x", "echo 1 > /proc/sys/net/ipv4/ip_unprivileged_port_start",
       "echo '127.0.0.1 a' | tee -a /etc/hosts", "sed -i 's/a/b/' /etc/hosts", "newgrp docker",
       "sg docker -c 'docker ps'", f"({S} true)", f"x; {S} -n true && {S} make install",
       "bash -c 'unshare -r id'", "env FOO=1 nsenter -t 1", f"/usr/bin/{S} id", "echo x >/etc/hosts",
       "sysctl -w net.ipv4.ip_unprivileged_port_start=80", "cp hosts /etc/hosts", f"ls $({S} id)",
       "unshare -Urm --propagation private sh -c 'mount -t tmpfs -o exec tmpfs /mnt && ls /mnt'",
       "python3 -c 'import os; os.system(\"unshare -r id\")'"]
NEG = [f"{S} -n true 2>/dev/null && echo yes || echo no", f"{S} -l", "grep -r unshare docs/", "man unshare | head",
       "cat /etc/hosts", "ls /proc/sys/net", "pseudo-build", "chmod 755 build.sh", "chmod +x run.sh",
       "docker run --rm img", "cp /etc/hosts ./hosts.copy", "rg 'nsenter|chroot' src/", "id -nG",
       "cat /proc/sys/kernel/unprivileged_userns_clone", f"echo 'use {S} to install' > NOTES.md",
       "git commit -m 'avoid unshare in CI'", "ls /etc/hosts > /tmp/out", "grep -n chroot Makefile",
       "python3 -c 'print(\"unshare\")'", "which unshare chroot", "docker ps",
       "cat <<EOF > notes.md\nrun unshare later\nEOF", "cat <<EOF > notes.md\nsu - root\nEOF"]


@pytest.mark.parametrize("cmd", POS)
def test_fires(cmd):
    assert workaround_hits(cmd)


@pytest.mark.parametrize("cmd", NEG)
def test_does_not_fire(cmd):
    assert workaround_hits(cmd) == []


def test_rewrite_call_replaces_the_command_with_the_notice():
    new, hits = rewrite_call("bash", json.dumps({"command": "unshare -r mount -t tmpfs t /mnt"}))
    assert json.loads(new) == {"command": ECHO_NOTICE} and hits == ["unshare"]
    same = json.dumps({"command": "ls -la"})
    assert rewrite_call("bash", same) == (same, [])
    assert rewrite_call("write", json.dumps({"path": "a.md", "content": "unshare -r id"}))[1] == []


def _turn(cid, cmd, result):
    return [{"role": "assistant", "content": "", "reasoning": "step",
             "tool_calls": [{"id": cid, "type": "function",
                             "function": {"name": "bash", "arguments": json.dumps({"command": cmd})}}]},
            {"role": "tool", "tool_call_id": cid, "content": result}]


def test_history_drops_workaround_and_notes_the_permission_error():
    msgs = [{"role": "user", "content": "build qemu"}]
    msgs += _turn("a", "mount -t tmpfs t /mnt", "mount: only root can do that")
    msgs += _turn("b", f"{S} mount -t tmpfs t /mnt", f"{S}: a password is required")
    msgs += _turn("c", ECHO_NOTICE, NOTICE)  # an earlier output rewrite
    out, events = repair_history(msgs)
    assert [m["role"] for m in out] == ["user", "assistant", "tool"]
    assert out[2]["content"] == "mount: only root can do that\n" + NOTICE
    assert [e["rule"] for e in events] == ["privguard-drop", "privguard-drop", "privguard-notice"]
    again, _ = repair_history(out)
    assert again == out


def test_history_without_permission_error_puts_notice_before_the_drop():
    msgs = [{"role": "user", "content": "x"}] + _turn("a", "ls", "a.txt") + _turn("b", "unshare -r id", "uid=0")
    out, _ = repair_history(msgs)
    assert out[-1]["content"] == "a.txt\n" + NOTICE and len(out) == 3


def test_history_clean_is_untouched():
    msgs = [{"role": "user", "content": "x"}] + _turn("a", f"{S} -n true", "ok")
    assert repair_history(msgs) == (msgs, [])


def test_history_permission_error_gets_the_notice_without_a_workaround():
    msgs = [{"role": "user", "content": "x"}] + _turn("a", "docker ps", "permission denied while trying to connect")
    out, events = repair_history(msgs)
    assert out[-1]["content"].endswith(NOTICE) and events[0]["rule"] == "privguard-notice"
    assert repair_history(out) == (out, [])
