#!/usr/bin/env python3
"""An example of an external keyward plugin.

It installs as an ordinary package: a directory with a `plugin.json` and this
file. It needs nothing beyond the standard library — a plugin must not ask a
person to assemble an environment merely to show a list of keys.

The conversation with the daemon: one JSON message at a time, `stdin` from
the daemon, `stdout` to the daemon, `stderr` into the daemon's log. Every
message is sealed — plugin protocol 2, see `noise.py` next to this file — and
nothing on the pipe is in the clear. The daemon sends `call` and `event`, the
plugin answers `result` and asks the core for things of its own through `host`.
"""

import json
import os
import sys
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import noise  # noqa: E402 - next to this file, the standard library only

# The channel comes first: the daemon opens it, we answer, and nothing is said
# before that.
_channel = noise.respond(sys.stdin.buffer, sys.stdout.buffer)

# Messages from the daemon that arrived while we waited for the core's answer.
# The daemon is free to send a call at any moment and it must not be lost: we
# answer as soon as the business at hand is finished.
_waiting = deque()
_host_id = 0


class Denied(Exception):
    """The core refused. A refusal is an answer, not a break: a plugin has to
    survive a no."""


def send(message):
    _channel.send(json.dumps(message, ensure_ascii=False).encode())


def receive():
    """The daemon's next message. `None` means it closed the pipe and it is time
    to leave."""
    raw = _channel.recv()
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError as e:
        print(f"the daemon's message would not parse: {e}", file=sys.stderr)
        return {}


def host(method, **args):
    """A request to the core. We wait for exactly our own answer and set the
    rest aside."""
    global _host_id
    _host_id += 1
    mine = _host_id
    send({"kind": "host", "id": mine, "method": method, "args": args})
    while True:
        message = receive()
        if message is None:
            sys.exit(0)
        if message.get("kind") == "host_result" and message.get("id") == mine:
            if message.get("error"):
                raise Denied(message["error"])
            return message.get("ok")
        _waiting.append(message)


def ssh_keys():
    """The vault's keys: a name and the hosts a key is bound to."""
    keys = []
    for entry in host("entries") or []:
        keys.append(
            {
                "name": entry.get("name") or "unnamed",
                "hosts": entry.get("kw-host") or "",
            }
        )
    return keys


def status():
    keys = ssh_keys()
    return {"unlocked": host("unlocked"), "count": len(keys), "keys": keys}


def call(action, _payload):
    if action == "status":
        return status()
    raise ValueError(f"I do not know the operation \"{action}\"")


def event(name):
    # The vault has been opened, which is the moment to say hello. Whoever has
    # a window shows the notification; a plugin needs neither a window nor any
    # right to the screen for that.
    if name != "unlocked":
        return
    try:
        count = len(ssh_keys())
        body = f"ssh keys in the vault: {count}"
    except Denied as e:
        body = f"we were not allowed to look at the keys: {e}"
    host("notice", title="Hello", body=body)


def main():
    while True:
        message = _waiting.popleft() if _waiting else receive()
        if message is None:
            break
        kind = message.get("kind")
        if kind == "call":
            answer = {"kind": "result", "id": message.get("id")}
            try:
                answer["ok"] = call(message.get("action"), message.get("payload"))
            except Denied as e:
                answer["error"] = str(e)
            except Exception as e:  # noqa: BLE001 - falling over leaves the daemon waiting
                answer["error"] = str(e)
            send(answer)
        elif kind == "event":
            try:
                event(message.get("event"))
            except Denied as e:
                print(f"the core refused: {e}", file=sys.stderr)
        else:
            print(f"an envelope that cannot be understood: {kind}", file=sys.stderr)


if __name__ == "__main__":
    main()
