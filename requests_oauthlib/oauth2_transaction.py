"""Per-round-trip authorization state for OAuth 2 authorization code flows.

An :class:`AuthorizationTransaction` owns the verification material for one
authorization round-trip: the ``state`` value, the PKCE code verifier and
method, the client identifier and the redirect URI.  Applications may persist
it with :meth:`AuthorizationTransaction.to_dict` and restore it with
:meth:`AuthorizationTransaction.from_dict`; the object never contains an
access token or a client secret.

The transaction is a one-shot capability.  Only the first successful token
exchange consumes it.  A failed exchange is classified explicitly:

* failures before a token request leaves the callback untouched and the
  transaction usable (for example a callback belonging to another transaction);
* transient HTTP (429 or 5xx) and network failures leave the transaction
  retryable;
* rejected grants, malformed responses and other terminal failures consume the
  transaction so a duplicate callback cannot replay the authorization code.
"""

import threading
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlparse

from oauthlib.oauth2 import OAuth2Error


STATUS_PENDING = "pending"
STATUS_EXCHANGING = "exchanging"
STATUS_CONSUMED = "consumed"
STATUS_FAILED = "failed"

_STATUSES = (STATUS_PENDING, STATUS_EXCHANGING, STATUS_CONSUMED, STATUS_FAILED)
_PKCE_METHODS = ("S256", "plain")


class AuthorizationTransactionError(OAuth2Error):
    """Base class for errors raised while handling an authorization transaction."""

    error = "invalid_request"
    description = "The authorization transaction cannot be used."


class AuthorizationTransactionConsumedError(AuthorizationTransactionError):
    """Raised when a transaction can no longer be exchanged.

    This covers a successful exchange (duplicate callbacks) as well as a
    terminal failure such as ``invalid_grant``.  Neither case may send a second
    token request with the same verification material.
    """

    description = "The authorization transaction has already been consumed."


class AuthorizationTransactionInProgressError(AuthorizationTransactionError):
    """Raised when a concurrent exchange is already using the transaction."""

    description = "The authorization transaction is already being exchanged."


class AuthorizationTransactionRedirectUriError(AuthorizationTransactionError):
    """Raised when a callback does not belong to the transaction's redirect URI."""

    description = "The callback does not match the transaction's redirect URI."


class AuthorizationTransactionClientMismatchError(AuthorizationTransactionError):
    """Raised when a restored transaction is exchanged by another client."""

    description = "The transaction is bound to a different OAuth client."


class AuthorizationTransactionRetryableError(AuthorizationTransactionError):
    """Raised for a transient exchange failure that may be retried.

    The transaction remains usable with exactly the same state, PKCE verifier,
    client and redirect URI.  The original exception is available as
    ``__cause__``.
    """

    description = "The token exchange failed transiently and may be retried."


def _optional_scope(scope):
    if scope is None:
        return None
    if isinstance(scope, str):
        return [part for part in scope.split(" ") if part]
    return list(scope)


class AuthorizationTransaction:
    """Verification material bound to one authorization code round-trip.

    Instances are created by :meth:`OAuth2Session.create_authorization_transaction`
    and are normally stored by the application between the authorization
    redirect and the callback.  Use :meth:`to_dict` for persistence and
    :meth:`from_dict` to restore the transaction before exchanging the code.
    """

    def __init__(
        self,
        state,
        authorization_url,
        client_id=None,
        client_type=None,
        redirect_uri=None,
        code_verifier=None,
        pkce=None,
        code_challenge=None,
        scope=None,
        status=STATUS_PENDING,
        retryable=False,
        failure=None,
    ):
        if not isinstance(state, str) or not state:
            raise ValueError("state must be a non-empty string.")
        if pkce not in (None,) + _PKCE_METHODS:
            raise ValueError("pkce must be 'S256', 'plain' or None.")
        if pkce and not code_verifier:
            raise ValueError("A PKCE transaction requires a code verifier.")
        if status not in _STATUSES:
            raise ValueError(
                "Unknown authorization transaction status: %r" % (status,)
            )
        if failure is not None and not isinstance(failure, Mapping):
            raise TypeError("failure must be a mapping or None.")

        self.state = state
        self.authorization_url = authorization_url
        self.client_id = client_id
        self.client_type = client_type
        self.redirect_uri = redirect_uri
        self.code_verifier = code_verifier
        self.pkce = pkce
        self.code_challenge = code_challenge
        self.scope = _optional_scope(scope)
        self._status = status
        self._retryable = bool(retryable)
        self._failure = dict(failure) if failure is not None else None
        self._lock = threading.RLock()

    def __repr__(self):
        return (
            "AuthorizationTransaction(state=%r, client_id=%r, redirect_uri=%r, "
            "pkce=%r, status=%r, retryable=%r)"
            % (
                self.state,
                self.client_id,
                self.redirect_uri,
                self.pkce,
                self._status,
                self._retryable,
            )
        )

    @property
    def status(self):
        return self._status

    @property
    def retryable(self):
        """True only when a failed exchange may be retried with this transaction."""
        return self._status == STATUS_FAILED and self._retryable

    @property
    def failure(self):
        """A copy of the last terminal or retryable failure, or ``None``."""
        return dict(self._failure) if self._failure is not None else None

    @property
    def pending(self):
        return self._status == STATUS_PENDING

    @property
    def consumed(self):
        """True when no further exchange may use this transaction.

        A successful exchange and a terminal failure both make the
        transaction non-replayable.  A transient failure is retryable and
        therefore not consumed.
        """
        return self._status == STATUS_CONSUMED or (
            self._status == STATUS_FAILED and not self._retryable
        )

    @property
    def failed(self):
        return self._status == STATUS_FAILED

    @property
    def in_progress(self):
        return self._status == STATUS_EXCHANGING

    @property
    def usable(self):
        """True when the transaction can be exchanged right now."""
        return self.pending or self.retryable

    def matches_state(self, state):
        return state is not None and self.state == state

    def to_dict(self):
        """Return a JSON-serializable snapshot suitable for application storage.

        The snapshot contains the PKCE verifier, which is a secret.  Store it
        server-side (and preferably encrypted) and never log it.
        """
        return {
            "version": 1,
            "state": self.state,
            "authorization_url": self.authorization_url,
            "client_id": self.client_id,
            "client_type": self.client_type,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.code_verifier,
            "pkce": self.pkce,
            "code_challenge": self.code_challenge,
            "scope": list(self.scope) if self.scope is not None else None,
            "status": self._status,
            "retryable": self._retryable,
            "failure": dict(self._failure) if self._failure is not None else None,
        }

    @classmethod
    def from_dict(cls, data):
        """Restore a transaction previously produced by :meth:`to_dict`."""
        if not isinstance(data, Mapping):
            raise TypeError("Authorization transaction data must be a mapping.")
        version = data.get("version", 1)
        if version != 1:
            raise ValueError(
                "Unsupported authorization transaction version: %r" % (version,)
            )
        try:
            state = data["state"]
            authorization_url = data["authorization_url"]
        except KeyError as exc:
            raise ValueError(
                "Missing authorization transaction field: %s" % exc
            ) from exc
        return cls(
            state=state,
            authorization_url=authorization_url,
            client_id=data.get("client_id"),
            client_type=data.get("client_type"),
            redirect_uri=data.get("redirect_uri"),
            code_verifier=data.get("code_verifier"),
            pkce=data.get("pkce"),
            code_challenge=data.get("code_challenge"),
            scope=data.get("scope"),
            status=data.get("status", STATUS_PENDING),
            retryable=data.get("retryable", False),
            failure=data.get("failure"),
        )

    @staticmethod
    def state_from_response(authorization_response):
        """Extract exactly one ``state`` value from a callback URL.

        This is intended for routing a callback to a persisted transaction.
        Missing, empty or repeated ``state`` parameters are rejected rather
        than letting different parsers pick different values.
        """
        if not isinstance(authorization_response, str):
            raise TypeError("authorization_response must be a URL string.")
        query = urlparse(authorization_response).query
        values = [
            value
            for name, value in parse_qsl(query, keep_blank_values=True)
            if name == "state"
        ]
        if len(values) != 1 or not values[0]:
            raise ValueError(
                "Authorization response must contain exactly one state value."
            )
        return values[0]

    def _begin_exchange(self):
        with self._lock:
            if self._status == STATUS_EXCHANGING:
                raise AuthorizationTransactionInProgressError()
            if not self.usable:
                raise AuthorizationTransactionConsumedError()
            previous = (self._status, self._retryable)
            self._status = STATUS_EXCHANGING
            return previous

    def _restore(self, previous):
        with self._lock:
            self._status, self._retryable = previous

    def _consume(self):
        with self._lock:
            self._status = STATUS_CONSUMED
            self._retryable = False
            self._failure = None

    def _fail(self, retryable, exc=None, status_code=None):
        failure = {"type": type(exc).__name__ if exc is not None else "ExchangeError"}
        error = getattr(exc, "error", None)
        if error:
            failure["error"] = error
        if status_code is not None:
            failure["status_code"] = status_code
        with self._lock:
            self._status = STATUS_FAILED
            self._retryable = bool(retryable)
            self._failure = failure

    def _mark_retryable_failure(self, exc=None, status_code=None):
        self._fail(True, exc=exc, status_code=status_code)

    def _mark_terminal_failure(self, exc=None, status_code=None):
        self._fail(False, exc=exc, status_code=status_code)
