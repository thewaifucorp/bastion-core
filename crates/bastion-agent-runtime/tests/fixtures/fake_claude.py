#!/usr/bin/env python3
"""Stand-in for the `claude` binary in stream-json mode, for adapter tests.

Speaks the subset of Claude Code 2.1's `-p --input-format stream-json
--output-format stream-json --permission-prompt-tool stdio` protocol the
adapter uses: `user` frames in; `system`/`assistant`/`user`/`result` frames
out; `control_request` `can_use_tool` out and `control_response` in;
`control_request` `interrupt` in.

The prompt picks the scenario:
  PERMISSION / EDIT  asks to Write (or Edit) a file, acts on the answer
  ARTIFACT           writes a file without asking (as if pre-allowed)
  NEVER              never finishes until interrupted
  GARBAGE            prints a human line on stdout
  CONTROL            sends an unsupported control request first
  CRASH              exits mid-turn
  anything else      replies "ok"

When FAKE_CLAUDE_LOG is set, appends one JSON object per line to it:
{"argv": [...]}, {"env": [...names...]}, {"mcp": <config>}, {"in": <frame>}.
Conversations created with --session-id are remembered in
.fake-claude-sessions under the working directory; --resume of any other id
fails the way Claude Code does.
"""

import json
import os
import sys

LOG = os.environ.get("FAKE_CLAUDE_LOG")
SESSIONS = os.path.join(os.getcwd(), ".fake-claude-sessions")


def log(entry):
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")


def send(frame):
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    frame = json.loads(line)
    log({"in": frame})
    return frame


def flag(name):
    args = sys.argv[1:]
    if name in args:
        i = args.index(name)
        return args[i + 1] if i + 1 < len(args) else ""
    return None


def result(ok, session, reason=None):
    frame = {
        "type": "result",
        "subtype": "success" if ok else "error_during_execution",
        "is_error": not ok,
        "session_id": session,
        "usage": {
            "input_tokens": 3,
            "cache_read_input_tokens": 10,
            "cache_creation_input_tokens": 5,
            "output_tokens": 2,
        },
    }
    if reason:
        frame["errors"] = [reason]
    send(frame)


def assistant(blocks):
    send({"type": "assistant", "message": {"role": "assistant", "content": blocks}})


def tool_result(tool_id, content, is_error):
    send({
        "type": "user",
        "message": {"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": tool_id,
            "content": content, "is_error": is_error,
        }]},
    })


def wait_control(request_id):
    """The response to our request, or None when an interrupt came first."""
    while True:
        frame = read()
        if frame.get("type") == "control_response":
            response = frame.get("response", {})
            if response.get("request_id") == request_id:
                return response
        elif is_interrupt(frame):
            ack(frame)
            return None


def is_interrupt(frame):
    return (frame.get("type") == "control_request"
            and frame.get("request", {}).get("subtype") == "interrupt")


def ack(frame):
    send({"type": "control_response", "response": {
        "subtype": "success", "request_id": frame.get("request_id"), "response": {}}})


def main():
    args = sys.argv[1:]
    if "--version" in args:
        print("2.1.284 (Claude Code)")
        return
    log({"argv": args})
    log({"env": sorted(os.environ.keys())})
    config = flag("--mcp-config")
    if config:
        with open(config) as f:
            log({"mcp": json.load(f)})
        if os.name == "posix":
            log({"mcp_mode": oct(os.stat(config).st_mode & 0o777)})

    known = []
    if os.path.exists(SESSIONS):
        with open(SESSIONS) as f:
            known = f.read().split()
    session = flag("--resume")
    if session is not None:
        if session not in known:
            send({"type": "result", "subtype": "error_during_execution", "is_error": True,
                  "session_id": session, "usage": {},
                  "errors": ["No conversation found with session ID: " + session]})
            sys.exit(1)
    else:
        session = flag("--session-id") or "no-session"
        with open(SESSIONS, "a") as f:
            f.write(session + "\n")

    mode = flag("--permission-mode") or "default"
    turn = 0
    while True:
        frame = read()
        if is_interrupt(frame):
            ack(frame)
            continue
        if frame.get("type") != "user":
            continue
        turn += 1
        prompt = frame["message"]["content"]
        send({"type": "system", "subtype": "init", "session_id": session,
              "permissionMode": mode, "apiKeySource": "none", "cwd": os.getcwd()})

        if "GARBAGE" in prompt:
            sys.stdout.write("Welcome to Claude Code!\n")
            sys.stdout.flush()
            continue
        if "CRASH" in prompt:
            assistant([{"type": "text", "text": "about to fail"}])
            sys.exit(3)
        if "NEVER" in prompt:
            assistant([{"type": "text", "text": "working on it"}])
            while True:
                nxt = read()
                if is_interrupt(nxt):
                    ack(nxt)
                    result(False, session)
                    break
            continue
        if "CONTROL" in prompt:
            send({"type": "control_request", "request_id": "hook-1",
                  "request": {"subtype": "hook_callback", "callback_id": "x"}})
            response = wait_control("hook-1")
            log({"control_answer": response})
        if "ARTIFACT" in prompt:
            path = os.path.join(os.getcwd(), "artifact.txt")
            tool_id = "toolu_art_%d" % turn
            assistant([{"type": "tool_use", "id": tool_id, "name": "Write",
                        "input": {"file_path": path, "content": "artifact\n"}}])
            with open(path, "w") as f:
                f.write("artifact\n")
            tool_result(tool_id, "File created successfully", False)
            assistant([{"type": "text", "text": "wrote the artifact"}])
            result(True, session)
            continue
        if "PERMISSION" in prompt or "EDIT" in prompt:
            edit = "EDIT" in prompt
            path = os.path.join(os.getcwd(), "e.txt" if edit else "perm.txt")
            if edit:
                with open(path, "w") as f:
                    f.write("a\n")
                tool, tool_input = "Edit", {"file_path": path, "old_string": "a\n",
                                            "new_string": "b\nc\n"}
            else:
                tool, tool_input = "Write", {"file_path": path, "content": "granted\n"}
            tool_id = "toolu_perm_%d" % turn
            assistant([{"type": "thinking", "thinking": "I need to write"},
                       {"type": "tool_use", "id": tool_id, "name": tool, "input": tool_input}])
            request_id = "perm-%d" % turn
            send({"type": "control_request", "request_id": request_id, "request": {
                "subtype": "can_use_tool", "tool_name": tool, "display_name": tool,
                "input": tool_input, "description": os.path.basename(path),
                "tool_use_id": tool_id}})
            response = wait_control(request_id)
            if response is None:
                result(False, session)
                continue
            log({"permission_answer": response})
            decision = response.get("response", {})
            if decision.get("behavior") == "allow":
                with open(path, "w") as f:
                    f.write("b\nc\n" if edit else decision["updatedInput"]["content"])
                tool_result(tool_id, "done", False)
                assistant([{"type": "text", "text": "allowed"}])
                result(True, session)
            else:
                tool_result(tool_id, "The user doesn't want to proceed", True)
                if decision.get("interrupt"):
                    result(False, session)
                else:
                    assistant([{"type": "text", "text": "denied"}])
                    result(True, session)
            continue

        assistant([{"type": "text", "text": "ok"}])
        result(True, session)


main()
