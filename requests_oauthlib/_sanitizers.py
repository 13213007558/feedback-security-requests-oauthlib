"""Helpers to keep debug logs free of OAuth credentials.

Debug logging is invaluable when troubleshooting OAuth flows, but it must
never emit access tokens, refresh tokens or client secrets. The helpers
below strip or mask the places where such values may appear (URL query
strings and fragments, Authorization headers) while preserving the
information needed to locate the failing phase, status code and target.
"""

from urllib.parse import urlsplit, urlunsplit

SENSITIVE_HEADERS = frozenset(["authorization", "proxy-authorization"])

REDACTED = "<redacted>"


def sanitize_url(url):
    """Return the URL without query string or fragment.

    Credentials may travel in the query (e.g. ``force_querystring`` token
    requests, OAuth 1 ``SIGNATURE_TYPE_QUERY``) or in the fragment (implicit
    grant), so both are dropped. Scheme, host and path are kept to identify
    the target endpoint.
    """
    try:
        parts = urlsplit(url)
    except (TypeError, ValueError):
        return "<unparseable url>"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def redact_headers(headers):
    """Return a copy of the headers with credential-bearing values masked."""
    if not headers:
        return headers
    redacted = {}
    for key, value in headers.items():
        normalized = key.decode("latin-1") if isinstance(key, bytes) else key
        redacted[key] = REDACTED if normalized.lower() in SENSITIVE_HEADERS else value
    return redacted


def redact_request_kwargs(kwargs):
    """Return a copy of request keyword arguments with bodies masked.

    ``data``, ``params`` and ``json`` may carry credentials (e.g. a token
    request body or a ``force_querystring`` client secret).
    """
    if not kwargs:
        return kwargs
    return {
        key: REDACTED if key in ("data", "params", "json") else value
        for key, value in kwargs.items()
    }
