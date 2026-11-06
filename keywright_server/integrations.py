"""Resource setup catalog. Presets supply defaults; adapters and OAuth remain reusable."""
from dataclasses import dataclass

from .homelab import CONNECTORS


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
    oauth_origins: tuple[str, ...] = ()
    setup_url: str = ""
    default_user: str = "root"
    cli_setup_instructions: str = ""
    cli_verify_command: str = ""

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
        "coinstats", "CoinStats", "Crypto prices, portfolios, wallets, and news.", "Browser sign-in", "coinstats", "mcp",
        default_name="CoinStats", url="https://mcp.coinstats.app/mcp", auth_type="oauth",
        instructions="Name this connection, then continue to CoinStats to sign in and authorize access.",
        keywords="crypto cryptocurrency bitcoin ethereum defi exchange market portfolio wallet oauth cloud",
        oauth_origins=("https://api.coin-stats.com", "https://coinstats.app"),
    ),
    Integration(
        "coinbase", "Coinbase", "Portfolios, market data, and trading through the Coinbase CLI.",
        "CLI over SSH", "coinbase", "ssh", default_name="Coinbase", default_user="coinbase",
        instructions="Connect a host where the Coinbase CLI is installed and configured for the SSH user below.",
        keywords="crypto cryptocurrency bitcoin exchange portfolio balance orders trading cdp api key cli ssh",
        setup_url="https://docs.cdp.coinbase.com/coinbase-for-agents/skill.md",
        cli_setup_instructions="Configure the Coinbase CLI and CDP API key on the remote host, under the SSH account below.",
        cli_verify_command="coinbase balance",
    ),
    Integration(
        "robinhood", "Robinhood", "Accounts, portfolios, market data, and trading.",
        "Browser sign-in", "robinhood", "mcp", default_name="Robinhood",
        url="https://agent.robinhood.com/mcp/trading", auth_type="oauth",
        instructions="Name this connection, then continue to Robinhood to sign in and complete agent onboarding.",
        keywords="stocks equities options crypto brokerage investing watchlists orders oauth cloud",
        oauth_origins=("https://robinhood.com", "https://api.robinhood.com"),
        setup_url="https://robinhood.com/us/en/support/articles/agentic-trading-overview/",
    ),
    Integration(
        "doordash", "DoorDash", "Restaurants, menus, carts, and orders through dd-cli.",
        "CLI over SSH", "doordash", "ssh", default_name="DoorDash", default_user="doordash",
        instructions="Choose a managed host, install the CLI, and sign in with your approved DoorDash account.",
        keywords="food delivery restaurant grocery shopping menu cart order history beta token cli ssh dd-cli",
        setup_url="https://github.com/doordash-oss/doordash-cli",
        cli_setup_instructions=("Install dd-cli on a supported host and sign in under the SSH account below. "
                                "On a headless host, securely supply DD_CLI_ACCESS_TOKEN to the remote command "
                                "environment using a token exported from a signed-in machine. "
                                "Keep tokens out of command arguments and Keywright descriptions."),
        cli_verify_command='dd-cli order history --intent "Verify DoorDash access"',
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
    *(Integration(key, connector.title, connector.description, "Read-only API", key, "mcp",
                  adapter=key, default_name=connector.title.replace(" ", ""),
                  instructions=connector.instructions, keywords=connector.keywords)
      for key, connector in CONNECTORS.items()),
)
GENERICS = (
    Integration("ssh", "SSH host", "Connect a server by its address and SSH account.", "SSH key", "ssh", "ssh"),
    Integration("mcp", "MCP server", "Use any Streamable HTTP server with OAuth or headers.", "Custom connection", "mcp", "mcp"),
    Integration("llm", "LLM gateway", "Connect a LiteLLM gateway with models and spending limits.", "API key", "llm", "llm"),
)
PRESET_BY_ID = {item.id: item for item in PRESETS}


def for_resource(resource) -> Integration | None:
    config = resource.config or {}
    if preset := PRESET_BY_ID.get(config.get("integration")):
        return preset if preset.kind == resource.kind else None
    if resource.kind != "mcp":
        return None
    if preset := PRESET_BY_ID.get(config.get("adapter")):
        return preset
    # Recognize Notion connections created before the catalog existed.
    if config.get("url", "").rstrip("/") == PRESET_BY_ID["notion"].url and config.get("auth_type") == "oauth":
        return PRESET_BY_ID["notion"]
    return None
