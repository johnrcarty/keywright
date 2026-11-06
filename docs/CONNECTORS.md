# Homelab connectors

These connectors are included in the 0.0.2 release candidate; they are not included
in the published v0.0.1 artifacts. Until 0.0.2 is published, install the server and
client from the same candidate checkout.

In **Resources → Add resource**, choose a service, enter its base address and
credential, save, and test the connection. The broker must be able to reach the
service. No sidecar MCP server, additional Python dependency or CLI installation
on the broker is needed. Credentials stay in the broker's resource configuration.

| Connector | Authentication | Tools in this initial implementation |
| --- | --- | --- |
| Proxmox VE | API token ID (`user@realm!name`) and secret | Cluster resources, nodes, node status, VM/LXC status |
| Pi-hole v6 | Application password | DNS summary, blocking status, installed versions |
| Home Assistant | Long-lived access token | API health, entity states, one entity's state, available services |
| Jellyfin | API key | Server information, libraries, playback sessions |
| Sonarr API v3 | API key | System status, health, series library, paginated download queue |
| Radarr API v3 | API key | System status, health, movie library, paginated download queue |
| authentik API v3 | Service account API token | Token identity, paginated users, groups, applications, providers, recent events |

All 28 tools read service data. They still require the same resource access,
policy checks, approvals and audit records as upstream MCP tools. Adding a resource
defaults to approval mode. They do not currently start/stop guests, change DNS
blocking, call Home Assistant services, or modify media libraries. For operations
outside this set, an existing upstream MCP resource or SSH host remains available
through its own access rules.

## Connection details

- **Proxmox:** use an HTTPS address such as `https://pve.example:8006`, with no
  `/api2/json` suffix. Create the token in Datacenter → Permissions → API Tokens.
  Give both the user and privilege-separated token the `PVEAuditor` role on the
  intended paths; propagate from `/` for cluster-wide reads. A token cannot exceed
  its user's permissions. Import the Proxmox CA into a bundle readable by the broker
  or use a publicly trusted certificate.
- **Pi-hole:** requires v6, not the legacy v5 API key. Use an application password
  from Settings → Web interface / API and the server address without `/admin` or
  `/api`. Each tool call signs in, reads its endpoint and releases its own session.
  This supports installations with 2FA without putting a TOTP secret on the broker.
- **Home Assistant:** create a long-lived token in the user's profile under
  Security. Use the server address without `/api`.
- **Jellyfin:** create a key in Dashboard → API Keys. Include the server's configured
  base path, if present, such as `https://media.example/jellyfin`. The connector uses
  `Authorization: MediaBrowser`, without requiring legacy authentication headers.
- **Sonarr/Radarr:** copy the key from Settings → General → Security. Include the
  configured URL Base, if present, such as `https://media.example/sonarr`. Sonarr
  v3/v4 use API v3; Radarr uses API v3.
- **authentik:** create a dedicated service account, then create a token under
  Directory → Tokens and App passwords with **Intent: API Token**, not App password.
  Use the server root, such as `https://authentik.example`, without `/api/v3` or
  `/if/admin`. This initial connector does not support installations under a URL
  subpath. Grant the service account only the relevant View permissions for users,
  groups, applications, the provider types you expose, and events. The token inherits
  that account's permissions; it does not need superuser access. Test connection
  checks `/core/users/me/`, so a successful probe confirms the token's identity,
  not permission to read every directory or event endpoint. A denied operation
  reports HTTP 403 without disclosing the upstream body.

HTTPS verification is on by default. Advanced TLS settings accept a CA bundle path
on the broker, or an explicit verification opt-out for a self-signed service.
Except for Proxmox, HTTP is supported for local services that lack TLS; credentials
then travel without transport encryption. Prefer HTTPS. Redirects are not followed.
Leaving the credential blank when editing preserves it; entering a new value rotates it.

Agents discover the actual resource name and schemas through MCP or `kw`:

```bash
kw resources
kw tool ProxmoxVE --list
kw tool ProxmoxVE proxmox_list_resources -r "Inventory the cluster"
kw tool ProxmoxVE proxmox_get_guest_status node=pve1 guest_type=qemu vmid=101 -r "Check VM status"
kw tool Pi-hole pihole_get_summary -r "Check DNS health"
kw tool HomeAssistant ha_get_state entity_id=sensor.temperature -r "Read temperature"
kw tool Sonarr sonarr_list_queue page=1 page_size=25 -r "Check download progress"
kw tool authentik authentik_get_current_user -r "Check connector identity"
kw tool authentik authentik_list_users search=alice page_size=25 -r "Find the user"
kw tool authentik authentik_list_events page=1 page_size=25 -r "Inspect recent authentication events"
```

Responses are capped at 2 MiB. Queue and authentik list tools support pagination; other list endpoints
currently return the upstream collection in one response and fail clearly if it
exceeds the limit. API errors omit upstream response bodies. Exact reflected
connector credentials are removed from successful results, but returned service
data can still contain private hostnames, paths, entity attributes or media details.

authentik lists default to 25 results per page (maximum 100), accept `search`, and
return numeric pagination metadata. Fetch subsequent pages explicitly; the broker
never follows response-provided URLs. Events are ordered newest first. Results
contain selected inventory fields: user/group IDs and membership IDs, application
and provider references, and basic event/actor information. Custom attributes,
nested provider objects, credentials, user settings and raw event context are
omitted. Account names, emails and event IP addresses remain sensitive service data
subject to Keywright's normal access rules. This connector does not change users,
memberships or policies, revoke sessions, reset passwords, or export tokens.

## Extending the catalog

`keywright_server/homelab.py` declares each connector's setup text and fixed GET
operations, and validates arguments before sending credentials. The integration
picker and proxy share that registry. Add argument models with strict validation
and explicit path/query mapping; never accept arbitrary URLs, methods or headers
from an agent. A new authentication protocol belongs in a dedicated adapter when
it needs more than this shared HTTP wrapper. Mutating tools need an explicit design
for approval scope, hazard classification, retry behavior and tests.

For services with a suitable remote MCP server, use the generic MCP connector.
For command-line tools installed on a managed host, use the existing SSH connector;
the broker does not execute downloaded CLI or stdio MCP packages locally.

To request a connector, use `kw issue connector --title "Service name" --body-file
request.txt` to preview, then add `--submit` to publish. Include API/MCP/CLI docs,
authentication method, service version, and the operations you need. Reports go
to the public Keywright repository using the caller's GitHub CLI login. See the
[client instructions](../client/README.md#bug-reports-and-connector-requests).

## Protocol references

The implementation uses the published interfaces below, with mocked protocol,
approval-boundary and admin-form tests. It has not been acceptance-tested against
live instances of all seven products.

- [Proxmox API token documentation](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc)
  and [API viewer](https://pve.proxmox.com/pve-docs/api-viewer/).
- [Pi-hole session authentication](https://docs.pi-hole.net/api/auth/)
  and [FTL routes](https://github.com/pi-hole/FTL/blob/master/src/api/api.c).
- [Home Assistant REST API](https://developers.home-assistant.io/docs/api/rest/).
- [Jellyfin API](https://api.jellyfin.org/), including the
  [authentication parser](https://github.com/jellyfin/jellyfin/blob/master/Jellyfin.Server.Implementations/Security/AuthorizationContext.cs),
  [library controller](https://github.com/jellyfin/jellyfin/blob/master/Jellyfin.Api/Controllers/LibraryStructureController.cs)
  and [session controller](https://github.com/jellyfin/jellyfin/blob/master/Jellyfin.Api/Controllers/SessionController.cs).
- [Sonarr OpenAPI](https://github.com/Sonarr/Sonarr/blob/develop/src/Sonarr.Api.V3/openapi.json)
  and [Radarr OpenAPI](https://github.com/Radarr/Radarr/blob/develop/src/Radarr.Api.V3/openapi.json).
- [authentik API](https://api.goauthentik.io/),
  [service-account tokens and permissions](https://docs.goauthentik.io/users-sources/user/account-types/service-accounts/),
  and [OpenAPI schema](https://github.com/goauthentik/authentik/blob/main/schema.yml).
