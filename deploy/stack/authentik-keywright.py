"""Run inside the Authentik Django shell. Provision only the Keywright OIDC application.

An existing application is verified, never silently repointed or granted new members.
The export mode prints credentials: use only via `kw capture` into a mode-0600 env file.
"""
import json
import os
import secrets
from urllib.parse import urlsplit

from authentik.core.models import Application, Group, User
from authentik.crypto.models import CertificateKeyPair
from authentik.flows.models import Flow
from authentik.policies.models import PolicyBinding
from authentik.providers.oauth2.models import OAuth2Provider, ScopeMapping
from django.db import transaction

SLUG = "keywright"
GROUP = "keywright-admins"


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Set {name} in the Authentik shell environment")
    return value


def origin(name):
    value = required(name)
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or any(c.isspace() for c in value)):
        raise ValueError(f"{name} must be an HTTPS origin without credentials, path, query or fragment")
    return value.rstrip("/")


PUBLIC_URL = origin("KEYWRIGHT_PUBLIC_URL")
AUTHENTIK_URL = origin("KEYWRIGHT_AUTHENTIK_URL")
CALLBACK = PUBLIC_URL + "/ui/oidc/callback"

with transaction.atomic():
    app = Application.objects.filter(slug=SLUG).first()
    if app is None:
        owner = User.objects.get(username=required("KEYWRIGHT_ADMIN_USERNAME"),
                                 email=required("KEYWRIGHT_ADMIN_EMAIL"), is_active=True)
        group, _ = Group.objects.get_or_create(name=GROUP)
        owner.ak_groups.add(group)
        signing_key = CertificateKeyPair.objects.get(pk=required("KEYWRIGHT_SIGNING_KEY_ID"))
        provider = OAuth2Provider.objects.create(
            name="Keywright OIDC", client_type="confidential",
            client_id=secrets.token_urlsafe(32), client_secret=secrets.token_urlsafe(48),
            authorization_flow=Flow.objects.get(slug="default-provider-authorization-implicit-consent"),
            invalidation_flow=Flow.objects.get(slug="default-provider-invalidation-flow"),
            signing_key=signing_key, sub_mode="hashed_user_id", issuer_mode="per_provider",
            include_claims_in_id_token=True,
            _redirect_uris=[{"url": CALLBACK, "matching_mode": "strict"}],
        )
        mappings = [ScopeMapping.objects.get(name=f"authentik default OAuth Mapping: OpenID '{scope}'")
                    for scope in ("openid", "profile", "email")]
        provider.property_mappings.set(mappings)
        app = Application.objects.create(name="Keywright", slug=SLUG, provider=provider,
                                         meta_launch_url=PUBLIC_URL + "/ui",
                                         policy_engine_mode="all")
        PolicyBinding.objects.create(target=app, group=group, order=0, enabled=True)
    else:
        provider = OAuth2Provider.objects.get(pk=app.provider_id)
        assert provider.name == "Keywright OIDC", "Existing application is not managed by this script"
        assert provider._redirect_uris == [{"url": CALLBACK, "matching_mode": "strict"}]
        assert provider.issuer_mode == "per_provider" and provider.signing_key_id
        assert PolicyBinding.objects.filter(target=app, group__name=GROUP, enabled=True).exists()

if os.environ.get("KEYWRIGHT_EXPORT_OIDC") == "1":
    # Do not run export interactively or send this output through agent context/logs.
    print("KW_AUTH_MODE=both")
    print("KW_OIDC_ISSUER=" + AUTHENTIK_URL + "/application/o/" + SLUG + "/")
    print("KW_OIDC_CLIENT_ID=" + provider.client_id)
    print("KW_OIDC_CLIENT_SECRET=" + provider.client_secret)
    print("KW_OIDC_ADMIN_GROUP=" + GROUP)
    print("KW_OIDC_SESSION_TTL=3600")
else:
    print(json.dumps({"application": app.slug, "provider": provider.name,
                      "admin_group": GROUP, "callback": CALLBACK}))
