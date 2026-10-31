"""The optional provisioning script gets deployment identity only from its environment."""
import json
import runpy
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/stack/authentik-keywright.py"


@pytest.fixture
def provisioning(monkeypatch):
    models = SimpleNamespace(**{name: MagicMock() for name in (
        "Application", "Group", "User", "CertificateKeyPair", "Flow", "PolicyBinding",
        "OAuth2Provider", "ScopeMapping", "transaction",
    )})
    for module, names in {
        "authentik.core.models": ("Application", "Group", "User"),
        "authentik.crypto.models": ("CertificateKeyPair",),
        "authentik.flows.models": ("Flow",),
        "authentik.policies.models": ("PolicyBinding",),
        "authentik.providers.oauth2.models": ("OAuth2Provider", "ScopeMapping"),
        "django.db": ("transaction",),
    }.items():
        stub = ModuleType(module)
        for name in names:
            setattr(stub, name, getattr(models, name))
        monkeypatch.setitem(sys.modules, module, stub)
    for name, value in {
        "KEYWRIGHT_PUBLIC_URL": "https://broker.example.test/",
        "KEYWRIGHT_AUTHENTIK_URL": "https://identity.example.test/",
        "KEYWRIGHT_ADMIN_USERNAME": "fixture-admin",
        "KEYWRIGHT_ADMIN_EMAIL": "admin@example.test",
        "KEYWRIGHT_SIGNING_KEY_ID": "fixture-certificate",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("KEYWRIGHT_EXPORT_OIDC", raising=False)
    models.Application.objects.filter.return_value.first.return_value = None
    models.Application.objects.create.return_value.slug = "keywright"
    models.Group.objects.get_or_create.return_value = (MagicMock(), True)
    models.OAuth2Provider.objects.create.return_value.name = "Keywright OIDC"
    return models


def test_new_application_uses_explicit_identity_without_printing_it(provisioning, capsys):
    m = provisioning
    runpy.run_path(str(SCRIPT))
    m.User.objects.get.assert_called_once_with(
        username="fixture-admin", email="admin@example.test", is_active=True,
    )
    m.CertificateKeyPair.objects.get.assert_called_once_with(pk="fixture-certificate")
    values = m.OAuth2Provider.objects.create.call_args.kwargs
    assert values["_redirect_uris"] == [
        {"url": "https://broker.example.test/ui/oidc/callback", "matching_mode": "strict"},
    ]
    assert m.Application.objects.create.call_args.kwargs["meta_launch_url"] == "https://broker.example.test/ui"
    output = capsys.readouterr().out
    assert json.loads(output)["admin_group"] == "keywright-admins"
    for private in ("fixture-admin", "admin@example.test", "fixture-certificate", values["client_secret"]):
        assert private not in output


@pytest.mark.parametrize("value", ["", "http://broker.example.test", "https://user:pass@broker.example.test",
                                   "https://broker.example.test/path", "https://broker.example.test?token=x",
                                   "https://broker.example.test#fragment", "https://bro\nker.example.test"])
def test_invalid_origin_stops_before_database_changes(provisioning, monkeypatch, value):
    monkeypatch.setenv("KEYWRIGHT_PUBLIC_URL", value)
    with pytest.raises(ValueError, match="KEYWRIGHT_PUBLIC_URL"):
        runpy.run_path(str(SCRIPT))
    provisioning.transaction.atomic.assert_not_called()


def test_existing_application_never_enrolls_another_user(provisioning, monkeypatch, capsys):
    m = provisioning
    app = SimpleNamespace(slug="keywright", provider_id="fixture-provider")
    m.Application.objects.filter.return_value.first.return_value = app
    m.OAuth2Provider.objects.get.return_value = SimpleNamespace(
        name="Keywright OIDC", issuer_mode="per_provider", signing_key_id="fixture-certificate",
        _redirect_uris=[{"url": "https://broker.example.test/ui/oidc/callback", "matching_mode": "strict"}],
        client_id="fixture-client", client_secret="fixture-secret",
    )
    for name in ("KEYWRIGHT_ADMIN_USERNAME", "KEYWRIGHT_ADMIN_EMAIL", "KEYWRIGHT_SIGNING_KEY_ID"):
        monkeypatch.delenv(name)
    monkeypatch.setenv("KEYWRIGHT_EXPORT_OIDC", "1")
    runpy.run_path(str(SCRIPT))
    m.User.objects.get.assert_not_called()
    m.Group.objects.get_or_create.assert_not_called()
    output = capsys.readouterr().out
    assert "KW_OIDC_ISSUER=https://identity.example.test/application/o/keywright/" in output
    assert "KW_OIDC_CLIENT_SECRET=fixture-secret" in output
