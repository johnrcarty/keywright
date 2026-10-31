"""Resource setup catalog. Presets supply defaults; adapters and OAuth remain reusable."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Integration:
    id: str
    title: str
    description: str
    badge: str
    icon: str
    kind: str
    adapter: str = ""
    default_name: str = ""
    url: str = ""
    auth_type: str = "headers"
    instructions: str = ""
    keywords: str = ""

    @property
    def search_text(self) -> str:
        return f"{self.title} {self.description} {self.badge} {self.keywords}".lower()


PRESETS = (
    Integration(
        "notion", "Notion", "Pages, databases, and workspace search.", "Browser sign-in", "notion", "mcp",
        default_name="Notion", url="https://mcp.notion.com/mcp", auth_type="oauth",
        instructions="Name this connection, then continue to Notion to sign in and choose your workspace.",
        keywords="notes documents oauth cloud",
    ),
    Integration(
        "omada", "TP-Link Omada", "Sites, network devices, and connected clients.", "App credentials", "omada", "mcp",
        adapter="omada", default_name="Omada",
        instructions="Create an Open API app in your controller, then enter its address and app credentials below.",
        keywords="network wifi switches access points controller",
    ),
    Integration(
        "keywright", "Keywright inventory", "Hosts, topology, subnets, and IP allocations.", "Built in", "shield", "mcp",
        adapter="keywright", default_name="Keywright",
        instructions="Add Keywright's inventory tools for your agents. No account or credentials are needed.",
        keywords="local infrastructure devices",
    ),
)
GENERICS = (
    Integration("ssh", "SSH host", "Connect a server by its address and SSH account.", "SSH key", "ssh", "ssh"),
    Integration("mcp", "MCP server", "Use any Streamable HTTP server with OAuth or headers.", "Custom connection", "mcp", "mcp"),
    Integration("llm", "LLM gateway", "Connect a LiteLLM gateway with models and spending limits.", "API key", "llm", "llm"),
)
PRESET_BY_ID = {item.id: item for item in PRESETS}


def for_resource(resource) -> Integration | None:
    config = resource.config or {}
    if resource.kind != "mcp":
        return None
    if preset := PRESET_BY_ID.get(config.get("integration")):
        return preset
    if preset := PRESET_BY_ID.get(config.get("adapter")):
        return preset
    # Recognize Notion connections created before the catalog existed.
    if config.get("url", "").rstrip("/") == PRESET_BY_ID["notion"].url and config.get("auth_type") == "oauth":
        return PRESET_BY_ID["notion"]
    return None
