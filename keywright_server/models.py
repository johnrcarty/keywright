from __future__ import annotations

import secrets
from datetime import UTC, date, datetime
from typing import Any, ClassVar

from sqlalchemy import JSON, CheckConstraint, Date, DateTime, ForeignKey, Index, Integer, String, Text, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def now() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo otherwise)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(9)}"


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict] = {dict[str, Any]: JSON, list[Any]: JSON}


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (Index("knowledge_document_path", "resource_id", "path", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("doc"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String)
    current_revision: Mapped[str | None] = mapped_column(String, nullable=True)


class KnowledgeRevision(Base):
    __tablename__ = "knowledge_revisions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("rev"))
    document_id: Mapped[str] = mapped_column(ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String, default="documentation")
    sha256: Mapped[str] = mapped_column(String)
    # Markdown is immutable, content-addressed on disk. The database holds its provenance and index.
    source: Mapped[str] = mapped_column(Text, default="")
    source_version: Mapped[str] = mapped_column(String, default="")
    base_revision: Mapped[str | None] = mapped_column(String, nullable=True)
    proposed_by: Mapped[str | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    attribution: Mapped[str] = mapped_column(String, default="admin")
    rationale: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    link_version: Mapped[int | None] = mapped_column(Integer, nullable=True)


class KnowledgeLink(Base):
    __tablename__ = "knowledge_links"
    __table_args__ = (Index("knowledge_link_source_revision", "source_document_id", "source_revision_id"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("link"))
    source_document_id: Mapped[str] = mapped_column(ForeignKey("knowledge_documents.id", ondelete="CASCADE"))
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("knowledge_revisions.id", ondelete="CASCADE"))
    target_document_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="SET NULL"), nullable=True, index=True)
    target_ref: Mapped[str] = mapped_column(String)
    syntax: Mapped[str] = mapped_column(String)
    relation: Mapped[str] = mapped_column(String, default="references")
    origin: Mapped[str] = mapped_column(String, default="explicit")
    line_number: Mapped[int] = mapped_column(Integer)


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), index=True)
    revision_id: Mapped[str] = mapped_column(ForeignKey("knowledge_revisions.id", ondelete="CASCADE"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    section_path: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)


class MailMessage(Base):
    __tablename__ = "mail_messages"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String, index=True)
    uid: Mapped[str] = mapped_column(String)
    message_id: Mapped[str] = mapped_column(String, default="")
    sender: Mapped[str] = mapped_column(Text, default="")
    recipients: Mapped[list[Any]] = mapped_column(JSON, default=list)
    subject: Mapped[str] = mapped_column(Text, default="")
    date: Mapped[str] = mapped_column(String, default="")
    attachments: Mapped[list[Any]] = mapped_column(JSON, default=list)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, default="unprocessed", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    plan: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    receipts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    present: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class MailRule(Base):
    __tablename__ = "mail_rules"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("mailrule"))
    name: Mapped[str] = mapped_column(String)
    sender: Mapped[str] = mapped_column(String, default="")
    subject: Mapped[str] = mapped_column(String, default="")
    action: Mapped[str] = mapped_column(String, default="pdf")
    target: Mapped[str] = mapped_column(String, default="")
    enabled: Mapped[bool] = mapped_column(default=True)
    position: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class Agent(Base):
    """An identity that talks MCP to us. One bearer token each; revoking it revokes everything."""

    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("agt"))
    name: Mapped[str] = mapped_column(String, unique=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True)
    token_prefix: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")

    @property
    def disabled(self) -> bool:
        return self.disabled_at is not None


class Resource(Base):
    """Something an agent may want: an SSH host, an upstream MCP server, or an LLM gateway.

    `default_mode` is the answer when no policy or grant speaks:
      open      - allowed, audited
      approval  - ask a human
      locked    - never grantable from a notification; only an explicit policy in the UI
    """

    __tablename__ = "resources"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("res"))
    kind: Mapped[str] = mapped_column(String)  # ssh | mcp | llm
    name: Mapped[str] = mapped_column(String, unique=True)  # second path segment: ssh/<name>/...
    default_mode: Mapped[str] = mapped_column(String, default="approval")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)

    @property
    def path_prefix(self) -> str:
        return f"{self.kind}/{self.name}"


class MCPOAuthConnection(Base):
    """Broker-owned OAuth credentials, separate from agent-visible resource configuration."""

    __tablename__ = "mcp_oauth_connections"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("oauth"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), unique=True)
    config_key: Mapped[str] = mapped_column(String)
    generation: Mapped[str] = mapped_column(String, default=lambda: new_id("gen"))
    sealed_data: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="disconnected")
    lease_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class MCPOAuthFlow(Base):
    __tablename__ = "mcp_oauth_flows"
    state_hash: Mapped[str] = mapped_column(String, primary_key=True)
    connection_id: Mapped[str] = mapped_column(ForeignKey("mcp_oauth_connections.id", ondelete="CASCADE"))
    browser_hash: Mapped[str] = mapped_column(String)
    admin_hash: Mapped[str] = mapped_column(String)
    generation: Mapped[str] = mapped_column(String)
    sealed_data: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class Policy(Base):
    """A standing rule. `agent_id` NULL applies to every agent. `deny` always wins."""

    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("pol"))
    agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=True)
    pattern: Mapped[str] = mapped_column(String)
    constraints: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    effect: Mapped[str] = mapped_column(String)  # allow | deny
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String, default="ui")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class AccessRequest(Base):
    __tablename__ = "requests"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("req"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    patterns: Mapped[list[Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # e.g. {"command": ...}
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|approved|denied|expired
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decision_scope: Mapped[str | None] = mapped_column(String, nullable=True)  # once|session|ttl|always|deny
    decision_options: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    decided_via: Mapped[str | None] = mapped_column(String, nullable=True)
    deny_reason: Mapped[str] = mapped_column(Text, default="")
    # Jev's verdict (semantic.py), kept apart from `detail` so nothing a grant binds to changes.
    # none_as_null: "no verdict asked" is SQL NULL, not the JSON value null, so IS NOT NULL finds verdicts.
    semantic: Mapped[dict[str, Any] | None] = mapped_column(JSON(none_as_null=True), nullable=True)

    agent: Mapped[Agent] = relationship(lazy="joined")


class Grant(Base):
    """A temporary permission produced by a decision. `once` grants are consumed atomically."""

    __tablename__ = "grants"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("grt"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    pattern: Mapped[str] = mapped_column(String)
    constraints: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    scope: Mapped[str] = mapped_column(String)  # once | session | ttl
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    uses_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_id: Mapped[str | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    def is_active(self, at: datetime, session_id: str | None) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= at:
            return False
        if self.uses_remaining is not None and self.uses_remaining <= 0:
            return False
        # a session grant is bound to exactly one session id; one without any id is dead
        if self.scope == "session":
            return bool(self.session_id) and self.session_id == session_id
        return True


class ShoppingCart(Base):
    """Provider-observed linkage and durable submit reservation. A timeout never clears it."""
    __tablename__ = "shopping_carts"
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True)
    cart_id: Mapped[str] = mapped_column(String, primary_key=True)
    link: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    submit_state: Mapped[str | None] = mapped_column(String, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    request_ids: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)


class LlmKey(Base):
    """A LiteLLM virtual key minted for one approval on one LLM gateway. The key is the lease made
    concrete: it carries the approved models, the grant's lifetime and a hard spend ceiling, and it
    is deleted upstream the moment the grants behind it are revoked. Agents never see it; the
    broker uses it on their behalf."""

    __tablename__ = "llm_keys"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("lkey"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    request_id: Mapped[str | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"), nullable=True)
    grant_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    key: Mapped[str] = mapped_column(Text)  # the upstream secret; only ever sent to LiteLLM
    key_alias: Mapped[str] = mapped_column(String, default="")
    models: Mapped[list[Any]] = mapped_column(JSON, default=list)
    limits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # max_budget, rpm_limit, ...
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    def is_active(self, at: datetime) -> bool:
        return self.revoked_at is None and (self.expires_at is None or self.expires_at > at)


class Nudge(Base):
    """An agent asking the human to come back to the conversation: a question to answer, a choice to
    make, work to look at. It carries no authority and grants nothing; it is a tap on the shoulder,
    kept until the human clears it so the phone and the dashboard agree on what is outstanding."""

    __tablename__ = "nudges"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("ndg"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    context: Mapped[str] = mapped_column(String, default="")  # where the conversation is: host:directory
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    cleared_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    cleared_via: Mapped[str | None] = mapped_column(String, nullable=True)

    agent: Mapped[Agent] = relationship(lazy="joined")

    @property
    def open(self) -> bool:
        return self.cleared_at is None


class AuditEvent(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    agent_id: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_name: Mapped[str] = mapped_column(String, default="")
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tool: Mapped[str] = mapped_column(String)
    patterns: Mapped[list[Any]] = mapped_column(JSON, default=list)
    decision: Mapped[str] = mapped_column(String)  # allow|deny|locked|pending|error|approved|denied|revoked...
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AdminLoginFlow(Base):
    """Short-lived, browser-bound OIDC transaction; consumed before exchanging its code."""
    __tablename__ = "admin_login_flows"
    state_hash: Mapped[str] = mapped_column(String, primary_key=True)
    browser_hash: Mapped[str] = mapped_column(String)
    config_key: Mapped[str] = mapped_column(String)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AdminSession(Base):
    """Opaque browser sessions. Provider access/refresh/ID tokens are never retained."""
    __tablename__ = "admin_sessions"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    config_key: Mapped[str] = mapped_column(String)
    identity: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class Setting(Base):
    """Key/value store for everything configurable in the UI (notifier config, admin password hash...)."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, onupdate=now)


Index("ix_grants_agent", Grant.agent_id, Grant.revoked_at)
Index("ix_requests_status", AccessRequest.status, AccessRequest.created_at)
Index("ix_audit_ts", AuditEvent.ts)
Index("ix_nudges_open", Nudge.cleared_at, Nudge.created_at)
Index("ix_llm_keys_active", LlmKey.resource_id, LlmKey.revoked_at)


# Inventory describes infrastructure; none of these records confer agent permissions.
class InventoryAsset(Base):
    __tablename__ = "inventory_assets"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("asset"))
    name: Mapped[str] = mapped_column(String, unique=True)
    kind: Mapped[str] = mapped_column(String, default="physical")
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_assets.id"), nullable=True)
    site: Mapped[str] = mapped_column(String, default="")
    tags: Mapped[str] = mapped_column(String, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, onupdate=now)


class InventoryInterface(Base):
    __tablename__ = "inventory_interfaces"
    __table_args__ = (Index("uq_inventory_interface_name", "asset_id", "name", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("iface"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"))
    name: Mapped[str] = mapped_column(String)
    medium: Mapped[str] = mapped_column(String, default="unknown")
    mac: Mapped[str] = mapped_column(String, default="")
    attached_to_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_assets.id"), nullable=True)
    port: Mapped[str] = mapped_column(String, default="")


class InventorySubnet(Base):
    __tablename__ = "inventory_subnets"
    __table_args__ = (Index("uq_inventory_subnet_scope", "scope", "cidr", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("net"))
    name: Mapped[str] = mapped_column(String)
    cidr: Mapped[str] = mapped_column(String)
    scope: Mapped[str] = mapped_column(String, default="default")
    site: Mapped[str] = mapped_column(String, default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gateway: Mapped[str] = mapped_column(String, default="")
    dhcp_start: Mapped[str] = mapped_column(String, default="")
    dhcp_end: Mapped[str] = mapped_column(String, default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class InventoryAllocation(Base):
    __tablename__ = "inventory_allocations"
    __table_args__ = (Index("uq_inventory_address", "subnet_id", "address", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("addr"))
    subnet_id: Mapped[str] = mapped_column(ForeignKey("inventory_subnets.id"))
    interface_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_interfaces.id"), nullable=True)
    address: Mapped[str] = mapped_column(String)
    state: Mapped[str] = mapped_column(String, default="reserved")
    label: Mapped[str] = mapped_column(String, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, onupdate=now)


class InventoryResourceLink(Base):
    __tablename__ = "inventory_resource_links"
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"))


class DiscoveryRun(Base):
    __tablename__ = "inventory_discovery_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("sync"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String)
    source_fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String, default="running")
    count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String, default="")


class DiscoveryObservation(Base):
    __tablename__ = "inventory_discovery_observations"
    __table_args__ = (Index("uq_inventory_observation", "resource_id", "provider", "external_id", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("obs"))
    resource_id: Mapped[str] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String)
    external_id: Mapped[str] = mapped_column(String)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    previous: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("inventory_discovery_runs.id", ondelete="CASCADE"))


class DiscoveryLink(Base):
    __tablename__ = "inventory_discovery_links"
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_discovery_observations.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), index=True)
    interface_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_interfaces.id"), nullable=True)
    reviewed_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reviewed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


# Work records coordinate people and agents; they confer no infrastructure access.
class Project(Base):
    __tablename__ = "work_projects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("prj"))
    key: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    archived: Mapped[bool] = mapped_column(default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class Board(Base):
    __tablename__ = "work_boards"
    __table_args__ = (CheckConstraint(
        "(kind = 'general' AND key = 'kw' AND project_id IS NULL) OR "
        "(kind = 'project' AND key <> 'kw' AND project_id IS NOT NULL)", name="work_board_kind"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("brd"))
    key: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("work_projects.id"), unique=True, nullable=True)


class BoardAgentAccess(Base):
    __tablename__ = "work_board_agent_access"
    board_id: Mapped[str] = mapped_column(ForeignKey("work_boards.id"), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    read: Mapped[bool] = mapped_column(default=False)
    write: Mapped[bool] = mapped_column(default=False)
    claim: Mapped[bool] = mapped_column(default=False)
    request_human_action: Mapped[bool] = mapped_column(default=False)


class Task(Base):
    __tablename__ = "work_tasks"
    __table_args__ = (
        CheckConstraint("status IN ('backlog','ready','in_progress','blocked','review','done')", name="work_task_status"),
        CheckConstraint("priority BETWEEN 0 AND 3", name="work_task_priority"),
        CheckConstraint("version > 0", name="work_task_version"),
        CheckConstraint("(assignee_kind = 'agent' AND assignee_agent_id IS NOT NULL) OR "
                        "(assignee_kind IN ('owner','unassigned') AND assignee_agent_id IS NULL)",
                        name="work_task_assignee"),
        Index("work_task_board_order", "board_id", "status", "position"),
        Index("work_task_owner_queue", "assignee_kind", "archived", "status"),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("tsk"))
    board_id: Mapped[str] = mapped_column(ForeignKey("work_boards.id"))
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    acceptance: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="backlog")
    priority: Mapped[int] = mapped_column(Integer, default=2)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    labels: Mapped[list[Any]] = mapped_column(JSON, default=list)
    assignee_kind: Mapped[str] = mapped_column(String, default="unassigned")
    assignee_agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), nullable=True)
    creator: Mapped[str] = mapped_column(String)
    position: Mapped[int] = mapped_column(Integer, default=1024)
    version: Mapped[int] = mapped_column(Integer, default=1)
    archived: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class TaskActivity(Base):
    __tablename__ = "work_task_activity"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("act"))
    task_id: Mapped[str] = mapped_column(ForeignKey("work_tasks.id"), index=True)
    actor: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class TaskComment(Base):
    __tablename__ = "work_task_comments"
    __table_args__ = (Index("work_comment_retry", "task_id", "actor", "idempotency_key", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("cmt"))
    task_id: Mapped[str] = mapped_column(ForeignKey("work_tasks.id"), index=True)
    actor: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class TaskNotification(Base):
    __tablename__ = "work_task_notifications"
    __table_args__ = (Index("work_notification_event", "activity_id", "recipient", unique=True),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("ntf"))
    task_id: Mapped[str] = mapped_column(ForeignKey("work_tasks.id"), index=True)
    activity_id: Mapped[str] = mapped_column(ForeignKey("work_task_activity.id"))
    recipient: Mapped[str] = mapped_column(String, default="owner")
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    error: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
