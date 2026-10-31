from keywright_server.mcp_proxy import describe


def test_describe_unwraps_task_group_errors():
    e = ExceptionGroup("unhandled errors in a TaskGroup", [
        ExceptionGroup("inner", [ConnectionError("404 Not Found for url http://email-mcp:9557/mcp.")])])
    assert describe(e) == "ConnectionError: 404 Not Found for url http://email-mcp:9557/mcp."
    assert describe(ValueError("plain")) == "ValueError: plain"
