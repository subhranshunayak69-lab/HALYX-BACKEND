from typing import Any, Dict, Optional


def send_email(
    recipient: str,
    file: Optional[str] = None,
    body: Optional[str] = None,
) -> Dict[str, Any]:
    attachment_info = f" with attachment '{file}'" if file else ""
    return {
        "tool": "send_email",
        "status": "executed",
        "message": f"Email sent to {recipient}{attachment_info}",
    }


def read_file(path: str) -> Dict[str, Any]:
    return {
        "tool": "read_file",
        "status": "executed",
        "message": f"Read contents of '{path}'.",
    }


def delete_file(path: str) -> Dict[str, Any]:
    return {
        "tool": "delete_file",
        "status": "executed",
        "message": f"Deleted '{path}'.",
    }


def search_web(query: str) -> Dict[str, Any]:
    return {
        "tool": "search_web",
        "status": "executed",
        "message": f"Searched web for '{query}'.",
    }


TOOL_REGISTRY = {
    "send_email": send_email,
    "read_file": read_file,
    "delete_file": delete_file,
    "search_web": search_web,
}


def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    func = TOOL_REGISTRY.get(tool_name)
    if not func:
        return {
            "tool": tool_name,
            "status": "error",
            "message": f"Unknown tool '{tool_name}'",
        }

    try:
        return func(**arguments)
    except TypeError as err:
        return {
            "tool": tool_name,
            "status": "error",
            "message": f"Invalid arguments for '{tool_name}': {err}",
        }
