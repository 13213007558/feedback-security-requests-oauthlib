"""Optional audience binding policy for :class:`OAuth2Session`.

An OAuth 2.0 session often talks to several internal resource services.
Binding the access token (and any client credentials) to the set of
audiences the application was approved for makes sure a token minted for
one service is never presented to another one, even when the services are
served from the same host on different ports or under different paths.

The policy is deliberately transport agnostic: it only decides whether a
URL is part of the approved audience.  :class:`~requests_oauthlib.OAuth2Session`
is responsible for enforcing that decision both before a request is
prepared and again when a redirect is followed.
"""
from collections.abc import Callable, Collection
from urllib.parse import urlparse

__all__ = [
    "AudienceBindingPolicy",
    "AudienceViolationError",
    "build_audience_policy",
    "withhold_credentials",
]

# Form fields that carry the client's own credentials, in addition to the
# Authorization / Proxy-Authorization headers.
_CLIENT_CREDENTIAL_FIELDS = ("client_secret", "client_id")


class AudienceViolationError(Exception):
    """Raised when a request targets a URL outside of the approved audience.

    Only raised when the policy was configured with
    ``on_violation="raise"``.  By default credentials are withheld and the
    request is sent unauthenticated instead.
    """


def withhold_credentials(headers, data, kwargs):
    """Remove every credential from a request that leaves the audience.

    This covers bearer/basic authentication headers, explicit ``auth``
    arguments and, for form encoded bodies, the ``client_id`` /
    ``client_secret`` fields used by the token endpoints.
    """
    if headers:
        headers.pop("Authorization", None)
        headers.pop("Proxy-Authorization", None)
    kwargs.pop("auth", None)
    if isinstance(data, dict):
        for field in _CLIENT_CREDENTIAL_FIELDS:
            data.pop(field, None)
    elif isinstance(data, (list, tuple)):
        filtered = [
            item
            for item in data
            if not (
                isinstance(item, (list, tuple))
                and item
                and item[0] in _CLIENT_CREDENTIAL_FIELDS
            )
        ]
        if isinstance(data, tuple):
            data = tuple(filtered)
        else:
            data = filtered
    return data


def _default_port(scheme):
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _parse_audience(origin):
    """Split an audience URL into a matchable (scheme, host, port, path)."""
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(
            "Audience entries must be absolute URLs including scheme and "
            "host, got %r." % origin
        )
    port = parsed.port
    if port is None:
        port = _default_port(parsed.scheme)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return parsed.scheme.lower(), parsed.hostname.lower(), port, path


class AudienceBindingPolicy:
    """Restrict which URLs may receive OAuth credentials.

    An audience is described by absolute URL prefixes, each pinning the
    scheme, host, port and a path scope.  Matching is exact on scheme, host
    and port (so ``https://api.example.com`` and
    ``https://api.example.com:8443`` are different audiences) while paths
    are matched by prefix on path segments, so an audience of
    ``https://host/v1`` covers ``https://host/v1/items`` but not
    ``https://host/v1other``.

    :param audiences: One or more absolute URL prefixes.
    :param on_violation: ``"withhold"`` (the default) strips every
        credential from requests leaving the audience and sends them
        unauthenticated; ``"raise"`` raises
        :class:`AudienceViolationError` instead.
    """

    def __init__(self, audiences, on_violation="withhold"):
        if on_violation not in ("withhold", "raise"):
            raise ValueError(
                "on_violation must be 'withhold' or 'raise', got %r."
                % on_violation
            )
        if isinstance(audiences, str) or not isinstance(audiences, Collection):
            audiences = [audiences]
        if not audiences:
            raise ValueError("At least one audience URL must be configured.")
        self.audiences = tuple(audiences)
        self.on_violation = on_violation
        self._rules = [_parse_audience(origin) for origin in self.audiences]

    @classmethod
    def from_callable(cls, callback, on_violation="withhold"):
        """Build a policy whose decision is delegated to ``callback(url)``.

        The callable receives the request URL as a string and must return a
        truthy value when the URL belongs to the approved audience.
        """
        if not isinstance(callback, Callable):
            raise TypeError("Expected a callable accepting a single URL.")

        class _CallableAudienceBindingPolicy(cls):
            def __init__(self):
                super(_CallableAudienceBindingPolicy, self).__init__(
                    ["https://callable.invalid/"], on_violation=on_violation
                )
                self.audiences = ()
                self._callback = callback

            def allows(self, url):
                return bool(self._callback(url))

        return _CallableAudienceBindingPolicy()

    def allows(self, url):
        """Return ``True`` when ``url`` falls inside the approved audience."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port
        except (ValueError, TypeError):
            return False
        if not parsed.scheme or not hostname:
            return False
        if port is None:
            port = _default_port(parsed.scheme)
        path = parsed.path or "/"
        for scheme, host, audience_port, audience_path in self._rules:
            if parsed.scheme.lower() != scheme:
                continue
            if hostname.lower() != host or port != audience_port:
                continue
            if path == audience_path or path.startswith(
                audience_path.rstrip("/") + "/"
            ):
                return True
        return False

    def __call__(self, url):
        return self.allows(url)


def build_audience_policy(audience, on_violation="withhold"):
    """Coerce the ``audience`` constructor argument into a policy object.

    Accepts an existing :class:`AudienceBindingPolicy`, a callable taking a
    URL, a single URL string or any collection of URL strings.  Returns
    ``None`` when no audience is configured, leaving the session
    unrestricted as before.
    """
    if audience is None:
        return None
    if isinstance(audience, AudienceBindingPolicy):
        return audience
    if isinstance(audience, Callable):
        return AudienceBindingPolicy.from_callable(
            audience, on_violation=on_violation
        )
    return AudienceBindingPolicy(audience, on_violation=on_violation)
