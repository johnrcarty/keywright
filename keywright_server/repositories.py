"""Repository context and metadata-only location management shared by UI, API and tools."""
import asyncio
import hashlib
import json
import re
import shlex
from datetime import timedelta
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, field_validator, model_validator
from sqlalchemy import func, or_, select, update

from . import audit, policy, ssh, tasks
from .db import session
from .discovery import source_fingerprint
from .models import (
    Board,
    BoardAgentAccess,
    InventoryAsset,
    InventoryResourceLink,
    Project,
    Repository,
    RepositoryLocation,
    Resource,
    now,
)

Environment = Literal['dev', 'test', 'prod']
Error = tasks.TaskError


def safe_text(value):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control characters are not allowed.')
    return value


def url(value):
    if not value:
        return ''
    safe_text(value)
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP(S) URL without credentials.')
    return value


def path(value, absolute):
    safe_text(value)
    if any(c in value for c in ('$', '`', '~', '{', '}', '\\')) or re.search(r'%\w+%', value):
        raise ValueError('Paths must be literal, without expansion placeholders.')
    p = PurePosixPath(value)
    if p.is_absolute() != absolute or '..' in p.parts or (absolute and not value):
        raise ValueError('Use an absolute directory and a relative subdirectory without parent traversal.')
    return value


class RepositorySave(tasks.Input):
    name: str = Field(min_length=1, max_length=120)
    project_id: str | None = None
    description: str = Field(default='', max_length=4000)
    web_url: str = Field(default='', max_length=1000)
    archived: bool = False
    expected_version: int | None = Field(default=None, ge=1)

    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError('Name is required.')
        return safe_text(value.strip())

    @field_validator('web_url')
    @classmethod
    def clean_url(cls, value):
        return url(value)


class LocationSave(tasks.Input):
    environment: Environment
    name: str = Field(min_length=1, max_length=120)
    asset_id: str | None = None
    resource_id: str | None = None
    directory: str = Field(min_length=1, max_length=4096)
    directory_kind: Literal['checkout', 'deployment_directory'] = 'checkout'
    expected_ref: str = Field(default='', max_length=240)
    subdirectory: str = Field(default='', max_length=4096)
    application_url: str = Field(default='', max_length=1000)
    notes: str = Field(default='', max_length=4000)
    is_primary: bool = False
    expected_version: int | None = Field(default=None, ge=1)

    @model_validator(mode='after')
    def validate_fields(self):
        if not self.asset_id and not self.resource_id:
            raise ValueError('Choose an inventory host or SSH resource.')
        if not self.name.strip():
            raise ValueError('Name is required.')
        safe_text(self.name)
        safe_text(self.expected_ref)
        path(self.directory, True)
        if self.subdirectory:
            path(self.subdirectory, False)
        url(self.application_url)
        return self


class RepositoryFilter(tasks.Input):
    project_id: str | None = None
    q: str = Field(default='', max_length=120)
    include_archived: bool = False
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=50, ge=1, le=100)


class Locations(tasks.Input):
    repository_id: str
    environment: Environment | None = None
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=50, ge=1, le=100)


class Context(tasks.Input):
    repository_id: str
    environment: Environment
    location_id: str | None = None


async def require_repo(db, repository_id, agent=None):
    await tasks.active_agent(db, agent)
    row = await db.get(Repository, repository_id)
    if not row:
        raise Error('not_found', 'Repository not found.')
    if agent:
        board = await db.scalar(select(Board).where(Board.project_id == row.project_id)) if row.project_id else None
        if not board:
            raise Error('forbidden', 'Repository has no authorized project.')
        await tasks.board_access(db, board.id, agent)
    return row


def repo_values(row, detail=False):
    keys = ('id', 'name', 'project_id', 'web_url', 'provider_host', 'provider_id', 'archived', 'version')
    return {k: getattr(row, k) for k in (*keys, 'description', 'source_metadata', 'sync_connection_id', 'import_enabled', 'include_closed', 'poll_seconds') if detail or k in keys}


async def list_repositories(db, data: RepositoryFilter, agent=None):
    await tasks.active_agent(db, agent)
    stmt = select(Repository).outerjoin(Project, Project.id == Repository.project_id)
    if agent:
        stmt = stmt.join(Board, Board.project_id == Repository.project_id).join(
            BoardAgentAccess, BoardAgentAccess.board_id == Board.id).where(
            BoardAgentAccess.agent_id == agent.id, BoardAgentAccess.read.is_(True))
    if not data.include_archived:
        stmt = stmt.where(Repository.archived.is_(False), or_(Project.id.is_(None), Project.archived.is_(False)))
    if data.project_id:
        stmt = stmt.where(Repository.project_id == data.project_id)
    if data.q:
        stmt = stmt.where(Repository.name.icontains(data.q, autoescape=True))
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = list(await db.scalars(stmt.order_by(Repository.name, Repository.id).offset(data.offset).limit(data.limit)))
    return {'repositories': [repo_values(r) for r in rows], 'total': total,
            'next_offset': data.offset + data.limit if data.offset + data.limit < total else None}


async def save_repository(db, data: RepositorySave, repository_id=None):
    await tasks.lock(db)
    if data.project_id:
        project = await db.get(Project, data.project_id)
        if not project or project.archived:
            raise Error('invalid_arguments', 'Choose an active project.')
    row = await require_repo(db, repository_id) if repository_id else Repository()
    if repository_id and data.expected_version != row.version:
        raise Error('stale_version', 'Repository changed. Refresh and retry.', row.version)
    if repository_id and row.provider_id and data.web_url != row.web_url:
        raise Error('source_owned', 'GitHub owns this repository URL; refresh source metadata instead.')
    # A human changing ownership deliberately transfers repository context visibility.
    for key, value in data.model_dump(exclude={'expected_version'}).items():
        setattr(row, key, value)
    row.version = row.version + 1 if repository_id else 1
    db.add(row)
    await db.flush()
    await audit.record(db, tool='work.repository.save', decision='saved',
                       detail={'repository_id': row.id, 'project_id': row.project_id}, commit=False)
    await tasks.commit(db, 'repository', repository_id=row.id)
    return repo_values(row, True)


async def hosts(db, row):
    asset = await db.get(InventoryAsset, row.asset_id) if row.asset_id else None
    resource = await db.get(Resource, row.resource_id) if row.resource_id else None
    available = not ((row.asset_ref and not asset) or (row.resource_ref and (not resource or resource.kind != 'ssh')))
    if asset and resource:
        link = await db.get(InventoryResourceLink, resource.id)
        available = available and bool(link and link.asset_id == asset.id)
    return asset, resource, available


async def host_visible(db, agent, resource):
    if agent is None:
        return True
    if not resource or resource.kind != 'ssh':
        return False
    # Metadata reads neither consume grants nor request new access. Exact-operation grants
    # cannot authorize a different operation; ordinary broker checks still apply on execution.
    verdict = await policy.evaluate(db, agent, None, [resource.path_prefix + '/exec/git'], consume=False)
    return verdict.allowed


def fingerprint(row, resource, repo):
    return hashlib.sha256(json.dumps([source_fingerprint(resource.config), repo.web_url,
        row.asset_id, row.resource_id, row.directory, row.directory_kind, row.subdirectory, row.expected_ref],
        sort_keys=True).encode()).hexdigest()


async def location_values(db, row, repo, agent=None):
    asset, resource, available = await hosts(db, row)
    if not await host_visible(db, agent, resource):
        return {'id': row.id, 'environment': row.environment, 'restricted': True}
    keys = ('id', 'repository_id', 'environment', 'name', 'directory', 'directory_kind', 'expected_ref',
            'subdirectory', 'application_url', 'notes', 'is_primary', 'version', 'observed', 'verified_at',
            'verification_message', 'asset_ref', 'resource_ref')
    result = {k: getattr(row, k) for k in keys}
    result['verified_at'] = row.verified_at.isoformat() if row.verified_at else None
    state = row.verification_status
    if not available:
        state = 'unavailable'
    elif row.verified_at and ((state == 'verifying' and row.verified_at < now() - timedelta(minutes=2)) or
          row.verified_at < now() - timedelta(days=1) or
          (resource and row.verification_fingerprint != fingerprint(row, resource, repo))):
        state = 'stale'
    result.update(asset_id=row.asset_id, resource_id=row.resource_id, asset_name=asset.name if asset else None,
                  resource_name=resource.name if resource else None, available=available,
                  can_verify=available and bool(resource and resource.config.get('host_key')),
                  verification_status=state, restricted=False)
    return result


async def list_locations(db, data: Locations, agent=None):
    repo = await require_repo(db, data.repository_id, agent)
    stmt = select(RepositoryLocation).where(RepositoryLocation.repository_id == repo.id)
    if data.environment:
        stmt = stmt.where(RepositoryLocation.environment == data.environment)
    rows = list(await db.scalars(stmt.order_by(RepositoryLocation.environment, RepositoryLocation.name,
                    RepositoryLocation.id).offset(data.offset).limit(data.limit + 1)))
    return {'locations': [await location_values(db, r, repo, agent) for r in rows[:data.limit]],
            'next_offset': data.offset + data.limit if len(rows) > data.limit else None}


async def context(db, data: Context, agent=None):
    repo = await require_repo(db, data.repository_id, agent)
    stmt = select(RepositoryLocation).where(RepositoryLocation.repository_id == repo.id,
                                          RepositoryLocation.environment == data.environment)
    if data.location_id:
        stmt = stmt.where(RepositoryLocation.id == data.location_id)
        row = await db.scalar(stmt)
        if not row:
            raise Error('not_found', 'Location is not configured for this repository/environment.')
    else:
        row = await db.scalar(stmt.where(RepositoryLocation.is_primary.is_(True)))
        if row is None:
            rows = list(await db.scalars(stmt.limit(2)))
            if not rows:
                raise Error('not_configured', f'No {data.environment} location configured.')
            if len(rows) > 1:
                raise Error('choice_required', 'Multiple locations have no primary. Supply a location_id.')
            row = rows[0]
    result = await location_values(db, row, repo, agent)
    if result['restricted']:
        raise Error('forbidden', 'Location details require existing SSH permission for this host.')
    if not result['available']:
        raise Error('unavailable_source', 'Location host or association is unavailable. An admin must update it.')
    return result


async def save_location(db, repository_id, data: LocationSave, location_id=None):
    await tasks.lock(db)
    repo = await require_repo(db, repository_id)
    project = await db.get(Project, repo.project_id) if repo.project_id else None
    if repo.archived or (project and project.archived):
        raise Error('invalid_transition', 'Unarchive this repository/project before editing locations.')
    row = await db.get(RepositoryLocation, location_id) if location_id else RepositoryLocation(repository_id=repo.id)
    if not row or row.repository_id != repo.id:
        raise Error('not_found', 'Location not found.')
    if location_id and row.version != data.expected_version:
        raise Error('stale_version', 'Location changed. Refresh and retry.', row.version)
    asset = await db.get(InventoryAsset, data.asset_id) if data.asset_id else None
    resource = await db.get(Resource, data.resource_id) if data.resource_id else None
    if (data.asset_id and not asset) or (data.resource_id and (not resource or resource.kind != 'ssh')):
        raise Error('invalid_arguments', 'Select an existing inventory host and/or SSH resource.')
    if asset and resource:
        link = await db.get(InventoryResourceLink, resource.id)
        if not link or link.asset_id != asset.id:
            raise Error('invalid_arguments', 'The SSH resource must be linked to this host in Inventory.')
    if data.is_primary:
        await db.execute(update(RepositoryLocation).where(RepositoryLocation.repository_id == repo.id,
            RepositoryLocation.environment == data.environment, RepositoryLocation.is_primary.is_(True),
            RepositoryLocation.id != (location_id or '')).values(is_primary=False, version=RepositoryLocation.version + 1))
    for key, value in data.model_dump(exclude={'expected_version'}).items():
        setattr(row, key, value)
    row.asset_ref, row.resource_ref = data.asset_id, data.resource_id
    row.version = row.version + 1 if location_id else 1
    row.verification_status, row.verification_message = 'unverified', ''
    row.verified_at, row.verification_fingerprint, row.observed = None, '', {}
    db.add(row)
    await db.flush()
    await audit.record(db, tool='work.location.save', decision='saved',
                       detail={'repository_id': repo.id, 'location_id': row.id}, commit=False)
    await tasks.commit(db, 'location', repository_id=repo.id)
    return await location_values(db, row, repo)


# A fixed read-only probe; every user value travels as quoted JSON, never shell code.
PROBE = r'''
import json, os, subprocess, sys
p = json.loads(sys.argv[1])
root = os.path.realpath(p['directory'])
app = os.path.realpath(os.path.join(root, p['subdirectory']))
result = {'exists': os.path.isdir(root), 'application_exists': os.path.isdir(app),
          'contained': os.path.commonpath([root, app]) == root}
if p['directory_kind'] == 'checkout' and result['exists']:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    def git(*args):
        r = subprocess.run(['git', '-C', root, *args], capture_output=True, timeout=8, env=env)
        return r.stdout.decode('utf-8', 'replace').strip()[:4000] if r.returncode == 0 else ''
    result.update(commit=git('rev-parse', '--verify', 'HEAD'), ref=git('symbolic-ref', '--quiet', '--short', 'HEAD'),
                  remote=git('config', '--no-includes', '--local', '--get', 'remote.origin.url'),
                  top=git('rev-parse', '--show-toplevel'))
    if p['expected_ref']:
        result['expected_commit'] = git('rev-parse', '--verify', '--end-of-options', p['expected_ref'] + '^{commit}')
print(json.dumps(result))
'''


def remote_identity(value):
    """Canonical GitHub identity only; discard any credentials and other remotes."""
    match = re.fullmatch(r'git@github\.com:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', value)
    if match:
        return 'https://github.com/' + match[1].removesuffix('.git').lower()
    try:
        parsed = urlsplit(value)
        if parsed.hostname != 'github.com' or parsed.scheme not in ('http', 'https', 'ssh'):
            return ''
        parts = parsed.path.strip('/').removesuffix('.git').split('/')
        if len(parts) != 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) for p in parts):
            return ''
        return urlunsplit(('https', 'github.com', '/' + '/'.join(parts).lower(), '', ''))
    except ValueError:
        return ''


async def verify_location(location_id, expected_version):
    """Explicit admin operation, like Inventory discovery; never exposed to agent tools."""
    async with session() as db:
        await tasks.lock(db)
        row = await db.get(RepositoryLocation, location_id)
        if not row:
            raise Error('not_found', 'Location not found.')
        repo = await require_repo(db, row.repository_id)
        _, resource, available = await hosts(db, row)
        if row.version != expected_version:
            raise Error('stale_version', 'Location changed. Refresh and retry.', row.version)
        if not available or not resource or not resource.config.get('host_key'):
            raise Error('unavailable_source', 'Verification requires a linked SSH resource with a pinned host key.')
        if row.verification_status == 'verifying' and row.verified_at and row.verified_at > now() - timedelta(minutes=2):
            raise Error('conflict', 'Verification is already running.')
        config = dict(resource.config)
        signature = fingerprint(row, resource, repo)
        values = {k: getattr(row, k) for k in ('directory', 'directory_kind', 'subdirectory', 'expected_ref')}
        expected_url = remote_identity(repo.web_url)
        row.version += 1
        version = row.version
        row.verification_status, row.verified_at = 'verifying', now()
        row.verification_fingerprint = signature
        await audit.record(db, tool='work.location.verify', decision='started',
                           detail={'location_id': row.id, 'resource_id': resource.id}, commit=False)
        await tasks.commit(db, 'location', repository_id=repo.id)
    status, message, observed = 'failed', 'Verification failed. Check host connectivity, Python 3 and Git availability.', {}
    try:
        command = 'python3 -c ' + shlex.quote(PROBE) + ' ' + shlex.quote(json.dumps(values))
        response = await asyncio.wait_for(ssh.run(config, command, timeout=45), timeout=55)
        if response.exit_code == 0 and not response.truncated and len(response.stdout) <= 16000:
            found = json.loads(response.stdout)
            observed = {k: str(found.get(k, ''))[:240] for k in ('ref', 'commit')}
            observed['repository'] = remote_identity(found.get('remote', ''))
            if not all(found.get(k) is True for k in ('exists', 'application_exists', 'contained')):
                status, message = 'mismatch', 'Directory missing, or application subdirectory missing/escaping its root.'
            elif values['directory_kind'] == 'deployment_directory':
                status, message, observed = 'verified', 'Deployment directory exists.', {}
            elif not re.fullmatch(r'[a-f0-9]{40,64}', observed['commit']):
                status, message = 'mismatch', 'No readable Git checkout found.'
            elif expected_url and observed['repository'] != expected_url:
                status, message = 'mismatch', 'Checkout remote does not match the registered repository URL.'
            elif values['expected_ref'] and found.get('expected_commit') != observed['commit']:
                status, message = 'mismatch', 'Observed commit does not match the expected revision.'
            elif not expected_url:
                status, message = 'partial', 'Checkout found; repository identity needs a registered GitHub URL to compare.'
            else:
                status, message = 'verified', 'Checkout identity and configured revision match.'
    except Exception:  # noqa: BLE001 — remote errors may contain secrets; persist only fixed messages.
        status, observed = 'failed', {}
    async with session() as db:
        await tasks.lock(db)
        row = await db.get(RepositoryLocation, location_id)
        repo = await require_repo(db, row.repository_id)
        _, resource, available = await hosts(db, row)
        if row.version != version or not available or not resource or fingerprint(row, resource, repo) != signature:
            raise Error('stale_version', 'Location or host changed during verification. Result discarded.', row.version)
        row.verification_status, row.verification_message, row.observed = status, message, observed
        row.verified_at, row.verification_fingerprint, row.version = now(), signature, version + 1
        await audit.record(db, tool='work.location.verify', decision=status, detail={'location_id': row.id}, commit=False)
        await tasks.commit(db, 'location', repository_id=repo.id)
        return await location_values(db, row, repo)
