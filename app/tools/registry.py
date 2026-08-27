"""
Halyx — Tool Registry
Fake-but-realistic tools our simulated agent can call. Every tool here
returns a mock result — no real emails get sent, no real files get deleted.
This lets us safely demo attacks without any real-world consequences.
"""

from typing import Any, Dict


def send_email(recipient: str, file: str = None, body: str = None) -> Dict[str, Any]:
    return {
        "tool": "send_email",
        "status": "executed",
        "message": f"Email sent to {recipient}" + (f" with attachment '{file}'" if file else ""),
    }


def read_file(path: str) -> Dict[str, Any]:
    return {
        "tool": "read_file",
        "status": "executed",
        "message": f"Read contents of '{path}' (simulated).",
    }


def delete_file(path: str) -> Dict[str, Any]:
    return {
        "tool": "delete_file",
        "status": "executed",
        "message": f"Deleted '{path}' (simulated).",
    }


def search_web(query: str) -> Dict[str, Any]:
    return {
        "tool": "search_web",
        "status": "executed",
        "message": f"Searched the web for '{query}' (simulated).",
    }


# Maps a tool name (string, as the agent would request it) to the real function
TOOL_REGISTRY = {
    "send_email": send_email,
    "read_file": read_file,
    "delete_file": delete_file,
    "search_web": search_web,
}


def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Actually runs a tool. Only ever called AFTER the interceptor approves it."""
    if tool_name not in TOOL_REGISTRY:
        return {"tool": tool_name, "status": "error", "message": f"Unknown tool '{tool_name}'"}
    return TOOL_REGISTRY[tool_name](**arguments)