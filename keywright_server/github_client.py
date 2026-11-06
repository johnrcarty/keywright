"""Read-only GitHub REST transport. Secrets never leave the credential provider."""
import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import delete, select

from . import mcp_oauth
from .db import session
from .models import GitHubCache, GitHubConnection, now

API_ORIGIN = 'https://api.github.com'
API_VERSION = '2026-03-10'
MAX_BYTES = 8 * 1024 * 1024
_locks = {}


class GitHubError(ValueError):
    def __init__(self, code, message, retry_at=None):
        super().__init__(message)
        self.code, self.retry_at = code, retry_at


def checked_url(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or parsed.hostname != 'api.github.com' or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.fragment or '\\' in value
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)):
            raise ValueError
        return value
    except ValueError:
        raise GitHubError('invalid_response', 'GitHub returned an unapproved API URL.') from None


class PATProvider:
    """Small credential interface; an App provider can implement authorization later."""
    @staticmethod
    def authorization(sealed):
        try:
            token = mcp_oauth.unseal(sealed)['token']
        except (mcp_oauth.ConnectionError, KeyError):
            raise GitHubError('credentials', 'Stored GitHub credentials cannot be opened. Replace the token.') from None
        return 'Bearer ' + token


def retry_time(headers):
    candidates = [now() + timedelta(seconds=60)]
    retry = headers.get('retry-after', '')
    if retry:
        try:
            candidates.append(now() + timedelta(seconds=max(0, int(retry))))
        except (ValueError, OverflowError):
            try:
                candidates.append(parsedate_to_datetime(retry).astimezone(UTC))
            except (TypeError, ValueError, OverflowError):
                pass
    if headers.get('x-ratelimit-remaining') == '0':
        try:
            candidates.append(datetime.fromtimestamp(int(headers['x-ratelimit-reset']), UTC))
        except (KeyError, ValueError, OverflowError, OSError):
            pass
    return max(candidates) + timedelta(seconds=1)


class Client:
    def __init__(self, connection_id, *, transport=None, provider=None):
        self.connection_id, self.transport = connection_id, transport
        self.provider = provider or PATProvider()
        self.version = None

    async def get(self, url):
        url = checked_url(url if url.startswith('https://') else API_ORIGIN + url)
        lock = _locks.setdefault(self.connection_id, asyncio.Lock())
        async with lock:
            async with session() as db:
                connection = await db.get(GitHubConnection, self.connection_id)
                if not connection or not connection.enabled:
                    raise GitHubError('paused', 'GitHub connection is disabled or unavailable.')
                if self.version is not None and self.version != connection.version:
                    raise GitHubError('changed', 'GitHub credentials changed. Retry the operation.')
                self.version = connection.version
                if connection.retry_at and connection.retry_at > now():
                    raise GitHubError('rate_limit', 'GitHub requests are waiting for the retry time.', connection.retry_at)
                authorization = self.provider.authorization(connection.sealed_data)
                signature = hashlib.sha256(json.dumps([connection.id, connection.version, API_VERSION, url]).encode()).hexdigest()
                cache = await db.get(GitHubCache, signature)
                if cache and cache.next_request_at and cache.next_request_at > now():
                    raise GitHubError('rate_limit', 'This GitHub endpoint is waiting for its polling interval.', cache.next_request_at)
                headers = {'Authorization': authorization, 'Accept': 'application/vnd.github+json',
                           'X-GitHub-Api-Version': API_VERSION, 'User-Agent': 'Keywright'}
                if cache:
                    if cache.etag:
                        headers['If-None-Match'] = cache.etag
                    if cache.modified:
                        headers['If-Modified-Since'] = cache.modified
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10), follow_redirects=False,
                                             transport=self.transport) as http:
                    current = url
                    for _ in range(5):
                        async with http.stream('GET', current, headers=headers) as response:
                            if response.status_code in (301, 302, 307, 308):
                                current = checked_url(urljoin(current, response.headers.get('location', '')))
                                continue
                            body = bytearray()
                            async for chunk in response.aiter_bytes():
                                body.extend(chunk)
                                if len(body) > MAX_BYTES:
                                    raise GitHubError('invalid_response', 'GitHub response exceeded the size limit.')
                            status, response_headers, links = response.status_code, response.headers, response.links
                            break
                    else:
                        raise GitHubError('invalid_response', 'Too many GitHub redirects.')
                if status == 304 and cache:
                    payload, next_url = cache.payload, cache.next_url
                elif status == 200:
                    payload = json.loads(body)
                    next_url = checked_url(links['next']['url']) if 'next' in links else ''
                elif status == 401:
                    raise GitHubError('credentials', 'GitHub token is expired or revoked. Replace it and test the connection.')
                elif status == 429 or (status == 403 and (response_headers.get('retry-after') or
                      response_headers.get('x-ratelimit-remaining') == '0' or b'secondary rate limit' in bytes(body).lower())):
                    raise GitHubError('rate_limit', 'GitHub rate limit reached. Refresh will retry after the required wait.',
                                      retry_time(response_headers))
                elif status in (403, 404):
                    raise GitHubError('unavailable', 'GitHub source is unavailable. Check token repository selection and read permissions.')
                elif status >= 500:
                    raise GitHubError('transient', 'GitHub is temporarily unavailable. Refresh will retry.',
                                      retry_time(response_headers) if response_headers.get('retry-after') else None)
                else:
                    raise GitHubError('invalid_response', 'GitHub rejected the request. Check connection settings and API support.')
            except (httpx.HTTPError, ValueError) as exc:
                if isinstance(exc, GitHubError):
                    error = exc
                else:
                    error = GitHubError('transient', 'GitHub request failed or returned invalid data. Refresh will retry.')
                async with session() as db:
                    connection = await db.get(GitHubConnection, self.connection_id)
                    if connection and connection.version == self.version:
                        connection.status, connection.error = error.code, str(error)
                        if error.retry_at:
                            connection.retry_at = error.retry_at
                        await db.commit()
                raise error from None
            async with session() as db:
                connection = await db.get(GitHubConnection, self.connection_id)
                if not connection or not connection.enabled or connection.version != self.version:
                    raise GitHubError('changed', 'GitHub connection changed during the request. Retry it.')
                connection.status, connection.error = 'connected', ''
                connection.retry_at = None
                poll = response_headers.get('x-poll-interval', '')
                if response_headers.get('x-ratelimit-remaining') == '0':
                    connection.retry_at = retry_time(response_headers)
                # Bound cached response size/count. Large pages are fetched normally next time.
                if len(body) <= 1024 * 1024 and (status == 200 or cache):
                    saved = await db.get(GitHubCache, signature)
                    if saved is None:
                        saved = GitHubCache(signature=signature, connection_id=self.connection_id)
                        db.add(saved)
                    saved.payload, saved.next_url, saved.touched_at = payload, next_url, now()
                    if poll.isdigit():
                        saved.next_request_at = now() + timedelta(seconds=int(poll))
                    if status == 200:
                        saved.etag = response_headers.get('etag', '')[:1000]
                        saved.modified = response_headers.get('last-modified', '')[:1000]
                    await db.flush()
                    old = list(await db.scalars(select(GitHubCache.signature).where(
                        GitHubCache.connection_id == self.connection_id).order_by(GitHubCache.touched_at.desc())
                        .offset(32).limit(1000)))
                    if old:
                        await db.execute(delete(GitHubCache).where(GitHubCache.signature.in_(old)))
                await db.commit()
            return payload, next_url
