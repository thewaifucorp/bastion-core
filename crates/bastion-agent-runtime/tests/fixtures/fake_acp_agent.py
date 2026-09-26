"""Minimal ACP agent for adapter tests: newline-delimited JSON-RPC on stdio.

On `session/prompt` it asks the client for permission to write a file (with a
diff), waits for the answer, streams one message chunk saying which option
was selected, and ends the turn. Everything it received that a test wants to
assert on (the `mcpServers` of `session/new`, the selected option) is written
to the JSON file named by argv[1].
"""

import json
import sys

log_path = sys.argv[1]
record = {}
next_id = 1000


def save():
    with open(log_path, "w") as f:
        json.dump(record, f)


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)


def wait_response(request_id):
    while True:
        message = read()
        if message.get("id") == request_id and "method" not in message:
            return message


while True:
    message = read()
    method = message.get("method")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": {},
                "authMethods": [],
                "agentInfo": {"name": "fake-acp", "version": "0.0.1"},
            },
        })
    elif method == "session/new":
        record["mcpServers"] = message["params"].get("mcpServers", [])
        save()
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"sessionId": "s1"}})
    elif method == "session/prompt":
        cwd_file = "/tmp/fake-acp-target.txt"
        next_id += 1
        send({
            "jsonrpc": "2.0",
            "id": next_id,
            "method": "session/request_permission",
            "params": {
                "sessionId": "s1",
                "toolCall": {
                    "toolCallId": "t1",
                    "title": "Write notes.txt",
                    "kind": "edit",
                    "content": [
                        {"type": "diff", "path": cwd_file, "oldText": None, "newText": "hello\n"}
                    ],
                },
                "options": [
                    {"optionId": "reject", "name": "Reject", "kind": "reject_once"},
                    {"optionId": "allow", "name": "Allow", "kind": "allow_once"},
                ],
            },
        })
        answer = wait_response(next_id)
        outcome = answer.get("result", {}).get("outcome", {})
        selected = outcome.get("optionId", outcome.get("outcome"))
        record["selected"] = selected
        save()
        send({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s1",
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": f"selected:{selected}"},
                },
            },
        })
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"stopReason": "end_turn"}})
    elif method == "session/cancel":
        pass
    elif "id" in message and method is not None:
        send({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": f"unsupported: {method}"},
        })
