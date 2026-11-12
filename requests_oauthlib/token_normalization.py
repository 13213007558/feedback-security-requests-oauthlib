"""Normalize and validate token responses from a two-version provider.

This module is deliberately independent from :class:`OAuth2Session`.  The
normalization adapter turns the provider's legacy and current token response
shapes into one canonical shape.  A separate validation boundary then decides
whether the normalized result is safe to hand to oauthlib.  Every decision is
recorded in a :class:`TokenNormalizationAudit`, together with the untouched raw
response body and the scope that was requested during authorization.

The adapter is intentionally allow-list based.  Unknown response fields are
quarantined in the audit record and never copied into the normalized token.
"""

import json
import math
import re
import time
from copy import deepcopy
from datetime import datetime


# Only these conversions are approved.  Keep this mapping and the migration
# document (docs/token_normalization_migration.rst) in sync.
FIELD_ALIASES = {
    "access_token": ("access_token", "accessToken"),
    "refresh_token": ("refresh_token", "refreshToken"),
    "token_type": ("token_type", "tokenType"),
    "expires_in": ("expires_in", "expiresIn"),
    "expires_at": ("expires_at", "expiresAt"),
}

_TOKEN_TYPES = {
    "bearer": "Bearer",
    "mac": "MAC",
}

_ERROR_FIELDS = ("error", "error_description", "error_uri")

_KNOWN_FIELDS = frozenset(
    [alias for aliases in FIELD_ALIASES.values() for alias in aliases]
    + ["scope"]
    + list(_ERROR_FIELDS)
)

_NUMERIC_STRING = re.compile(r"^[0-9]+$")


class TokenResponseError(ValueError):
    """Raised when a token response fails the validation boundary.

    The rejected :class:`TokenNormalizationAudit` is available as ``audit`` so
    callers can inspect the raw response, the scope relationship, and the
    reason for rejection.
    """

    def __init__(self, reason, audit=None):
        super(TokenResponseError, self).__init__(reason)
        self.reason = reason
        self.audit = audit


class TokenNormalizationAudit(object):
    """Immutable-by-convention record of one normalization decision.

    ``status`` is one of ``"accepted"``, ``"rejected"`` or
    ``"error_response"``.  ``normalized_token`` is only populated for accepted
    responses.  ``raw_token`` always contains a copy of the parsed original
    response when it was valid JSON.
    """

    def __init__(
        self,
        raw_body,
        raw_token=None,
        normalized_token=None,
        requested_scope=None,
        previous_scope=None,
        granted_scope=None,
        conversions=None,
        duplicate_fields=None,
        unknown_fields=None,
        status="rejected",
        reason=None,
        operation=None,
        evaluated_at=None,
        expiry_tolerance=None,
    ):
        self.raw_body = raw_body
        self.raw_token = deepcopy(raw_token)
        self.normalized_token = deepcopy(normalized_token)
        self.requested_scope = _scope_tuple(requested_scope)
        self.previous_scope = _scope_tuple(previous_scope)
        self.granted_scope = _scope_tuple(granted_scope)
        self.conversions = tuple(conversions or ())
        self.duplicate_fields = tuple(duplicate_fields or ())
        self.unknown_fields = deepcopy(unknown_fields or {})
        self.status = status
        self.reason = reason
        self.operation = operation
        self.evaluated_at = evaluated_at
        self.expiry_tolerance = expiry_tolerance

    def to_dict(self):
        """Return a JSON-serializable view for logging or review."""
        return {
            "status": self.status,
            "reason": self.reason,
            "operation": self.operation,
            "evaluated_at": self.evaluated_at,
            "expiry_tolerance": self.expiry_tolerance,
            "raw_body": self.raw_body,
            "raw_token": deepcopy(self.raw_token),
            "normalized_token": deepcopy(self.normalized_token),
            "requested_scope": list(self.requested_scope)
            if self.requested_scope is not None
            else None,
            "previous_scope": list(self.previous_scope)
            if self.previous_scope is not None
            else None,
            "granted_scope": list(self.granted_scope)
            if self.granted_scope is not None
            else None,
            "conversions": list(self.conversions),
            "duplicate_fields": list(self.duplicate_fields),
            "unknown_fields": deepcopy(self.unknown_fields),
        }

    def __repr__(self):
        return (
            "<TokenNormalizationAudit status={!r} operation={!r} "
            "requested_scope={!r} previous_scope={!r} granted_scope={!r}>"
        ).format(
            self.status,
            self.operation,
            self.requested_scope,
            self.previous_scope,
            self.granted_scope,
        )


def _scope_tuple(scope):
    """Return scopes as a tuple, preserving order; ``None`` stays ``None``."""
    if scope is None:
        return None
    if isinstance(scope, str):
        values = scope.split()
    elif isinstance(scope, (set, frozenset)):
        values = sorted(str(item) for item in scope)
    elif isinstance(scope, (list, tuple)):
        values = [str(item) for item in scope]
    else:
        raise TokenResponseError(
            "Scope must be a string, list, tuple, set, or None."
        )

    if any(not value for value in values):
        raise TokenResponseError("Scope values must be non-empty strings.")
    return tuple(values)


def _scope_from_response(value):
    if isinstance(value, str):
        values = value.split()
    elif isinstance(value, (list, tuple, set, frozenset)):
        if any(not isinstance(item, str) for item in value):
            raise TokenResponseError("Response scope must contain strings.")
        values = list(value)
    else:
        raise TokenResponseError(
            "Response scope must be a space-delimited string or a list."
        )

    if any(not value for value in values):
        raise TokenResponseError("Response scope values must be non-empty.")
    return tuple(values)


def _normalize_string(value, field, conversions):
    if not isinstance(value, str) or not value.strip():
        raise TokenResponseError("{} must be a non-empty string.".format(field))
    return value


def _normalize_expires_in(value, conversions):
    if isinstance(value, bool):
        raise TokenResponseError("expires_in must be a positive integer.")
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str):
        if not _NUMERIC_STRING.match(value.strip()):
            raise TokenResponseError(
                "expires_in must be a positive integer or a numeric string."
            )
        seconds = int(value)
        conversions.append("expires_in: numeric string -> int")
    elif isinstance(value, float) and value.is_integer():
        seconds = int(value)
        conversions.append("expires_in: integral float -> int")
    else:
        raise TokenResponseError("expires_in must be a positive integer.")

    if seconds <= 0:
        raise TokenResponseError("expires_in must be greater than zero.")
    return seconds


def _normalize_expires_at(value, now, conversions):
    if isinstance(value, bool):
        raise TokenResponseError("expires_at must be a future Unix timestamp.")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise TokenResponseError("expires_at must be a finite timestamp.")
        epoch = int(value)
        if isinstance(value, float):
            conversions.append("expires_at: numeric value -> int seconds")
    elif isinstance(value, str):
        text = value.strip()
        if _NUMERIC_STRING.match(text):
            epoch = int(text)
            conversions.append("expires_at: numeric string -> int seconds")
        else:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                raise TokenResponseError(
                    "expires_at must be an integer epoch or ISO-8601 timestamp."
                )
            if parsed.tzinfo is None:
                raise TokenResponseError(
                    "expires_at ISO-8601 timestamps must include a timezone."
                )
            epoch = int(parsed.timestamp())
            conversions.append("expires_at: ISO-8601 -> Unix seconds")
    else:
        raise TokenResponseError("expires_at must be an integer epoch or ISO-8601.")

    if epoch <= now:
        raise TokenResponseError("expires_at is not in the future.")
    return epoch


def _present_aliases(raw_token, canonical):
    return [key for key in FIELD_ALIASES[canonical] if key in raw_token]


def _resolve_equal(values, canonical, keys):
    """Resolve duplicate aliases, requiring all converted values to agree."""
    first = values[0]
    if any(value != first for value in values[1:]):
        raise TokenResponseError(
            "Conflicting values for {} aliases: {}.".format(
                canonical, ", ".join(keys)
            )
        )
    return first


def _rejected(
    raw_body,
    raw_token,
    requested_scope,
    reason,
    operation,
    evaluated_at,
    expiry_tolerance,
    unknown_fields=None,
    previous_scope=None,
):
    return TokenNormalizationAudit(
        raw_body=raw_body,
        raw_token=raw_token,
        requested_scope=requested_scope,
        previous_scope=previous_scope,
        status="rejected",
        reason=reason,
        operation=operation,
        evaluated_at=evaluated_at,
        expiry_tolerance=expiry_tolerance,
        unknown_fields=unknown_fields,
    )


def inspect_vendor_token_response(
    raw_body,
    requested_scope=None,
    operation=None,
    now=None,
    expiry_tolerance=5,
    previous_scope=None,
):
    """Normalize and validate a token response without touching a session.

    :param raw_body: The exact response body text (or bytes).
    :param requested_scope: The scope requested during authorization.  It is
        the authorization range against which any granted scope is checked.
    :param operation: Optional label such as ``"access_token"`` or
        ``"refresh_token"``, copied into the audit record.
    :param previous_scope: Scope granted to the token being replaced.  When
        present it caps the new grant as well, so a refresh cannot recover a
        scope that was requested but never granted.
    :param now: A Unix timestamp or zero-argument callable used as the
        evaluation time.  Defaults to ``time.time``.
    :param expiry_tolerance: Maximum allowed difference, in seconds, between
        ``expires_in`` and ``expires_at`` when both are supplied.
    :return: A :class:`TokenNormalizationAudit`.  Rejections are represented by
        ``status == "rejected"``; this function does not raise for bad input.
    """
    if now is None:
        now = time.time
    evaluated_at = int(now() if callable(now) else now)

    if (
        isinstance(expiry_tolerance, bool)
        or not isinstance(expiry_tolerance, (int, float))
        or expiry_tolerance < 0
    ):
        raise TokenResponseError(
            "expiry_tolerance must be zero or positive."
        )
    expiry_tolerance = float(expiry_tolerance)

    try:
        normalized_requested_scope = _scope_tuple(requested_scope)
        normalized_previous_scope = _scope_tuple(previous_scope)
    except TokenResponseError as exc:
        return _rejected(
            raw_body,
            None,
            None,
            str(exc),
            operation,
            evaluated_at,
            expiry_tolerance,
        )

    if (
        normalized_requested_scope is not None
        and normalized_previous_scope is not None
        and not set(normalized_previous_scope).issubset(
            set(normalized_requested_scope)
        )
    ):
        return _rejected(
            raw_body,
            None,
            normalized_requested_scope,
            "Previously granted scope is outside the requested range.",
            operation,
            evaluated_at,
            expiry_tolerance,
            previous_scope=normalized_previous_scope,
        )

    try:
        if isinstance(raw_body, bytes):
            decoded_body = raw_body.decode("utf-8")
        elif isinstance(raw_body, str):
            decoded_body = raw_body
        else:
            raise TypeError("raw_body must be text or bytes")
    except (TypeError, UnicodeError) as exc:
        return _rejected(
            raw_body,
            None,
            normalized_requested_scope,
            "Raw response is not UTF-8 text: {}".format(exc),
            operation,
            evaluated_at,
            expiry_tolerance,
            previous_scope=normalized_previous_scope,
        )

    try:
        raw_token = json.loads(decoded_body)
    except ValueError as exc:
        return _rejected(
            decoded_body,
            None,
            normalized_requested_scope,
            "Token response is not valid JSON: {}".format(exc),
            operation,
            evaluated_at,
            expiry_tolerance,
            previous_scope=normalized_previous_scope,
        )

    if not isinstance(raw_token, dict):
        return _rejected(
            decoded_body,
            raw_token,
            normalized_requested_scope,
            "Token response must be a JSON object.",
            operation,
            evaluated_at,
            expiry_tolerance,
            previous_scope=normalized_previous_scope,
        )

    raw_token = deepcopy(raw_token)
    unknown_fields = {
        key: value for key, value in raw_token.items() if key not in _KNOWN_FIELDS
    }

    # Error responses are passed through to oauthlib unchanged.  A response
    # that carries both an error and token material is ambiguous and rejected.
    if "error" in raw_token:
        has_token_material = any(
            key in raw_token
            for key in (
                "access_token",
                "accessToken",
                "refresh_token",
                "refreshToken",
                "expires_in",
                "expiresIn",
                "expires_at",
                "expiresAt",
            )
        )
        if has_token_material:
            return _rejected(
                decoded_body,
                raw_token,
                normalized_requested_scope,
                "Response contains both an error and token material.",
                operation,
                evaluated_at,
                expiry_tolerance,
                unknown_fields,
                previous_scope=normalized_previous_scope,
            )
        if not isinstance(raw_token.get("error"), str) or not raw_token["error"]:
            return _rejected(
                decoded_body,
                raw_token,
                normalized_requested_scope,
                "Error response must contain a non-empty string error code.",
                operation,
                evaluated_at,
                expiry_tolerance,
                unknown_fields,
                previous_scope=normalized_previous_scope,
            )
        return TokenNormalizationAudit(
            raw_body=decoded_body,
            raw_token=raw_token,
            requested_scope=normalized_requested_scope,
            previous_scope=normalized_previous_scope,
            status="error_response",
            reason="Authorization server returned an error response.",
            operation=operation,
            evaluated_at=evaluated_at,
            expiry_tolerance=expiry_tolerance,
            unknown_fields=unknown_fields,
        )

    conversions = []
    duplicates = []

    try:
        requested = normalized_requested_scope

        access_keys = _present_aliases(raw_token, "access_token")
        if not access_keys:
            raise TokenResponseError("Missing access_token.")
        access_values = [
            _normalize_string(raw_token[key], "access_token", conversions)
            for key in access_keys
        ]
        access_token = _resolve_equal(
            access_values, "access_token", access_keys
        )
        if len(access_keys) > 1:
            duplicates.append("access_token aliases agree: {}".format(
                ", ".join(access_keys)
            ))
        for key in access_keys:
            if key != "access_token":
                conversions.append("{}->access_token".format(key))

        refresh_keys = _present_aliases(raw_token, "refresh_token")
        refresh_token = None
        if refresh_keys:
            refresh_values = [
                _normalize_string(raw_token[key], "refresh_token", conversions)
                for key in refresh_keys
            ]
            refresh_token = _resolve_equal(
                refresh_values, "refresh_token", refresh_keys
            )
            if len(refresh_keys) > 1:
                duplicates.append("refresh_token aliases agree: {}".format(
                    ", ".join(refresh_keys)
                ))
            for key in refresh_keys:
                if key != "refresh_token":
                    conversions.append("{}->refresh_token".format(key))

        token_keys = _present_aliases(raw_token, "token_type")
        if not token_keys:
            raise TokenResponseError(
                "Missing token_type; it is not defaulted by this adapter."
            )
        token_types = []
        for key in token_keys:
            value = raw_token[key]
            if not isinstance(value, str) or not value.strip():
                raise TokenResponseError("token_type must be a non-empty string.")
            canonical = _TOKEN_TYPES.get(value.strip().lower())
            if canonical is None:
                raise TokenResponseError(
                    "Unsupported token_type {!r}; unknown types are not trusted."
                    .format(value)
                )
            token_types.append(canonical)
            if canonical != value:
                conversions.append("token_type: {!r} -> {!r}".format(value, canonical))
        token_type = _resolve_equal(token_types, "token_type", token_keys)
        if len(token_keys) > 1:
            duplicates.append("token_type aliases agree: {}".format(
                ", ".join(token_keys)
            ))
        for key in token_keys:
            if key != "token_type":
                conversions.append("{}->token_type".format(key))

        expires_in_keys = _present_aliases(raw_token, "expires_in")
        expires_at_keys = _present_aliases(raw_token, "expires_at")
        if not expires_in_keys and not expires_at_keys:
            raise TokenResponseError(
                "Missing expires_in/expires_at; token lifetime is not trusted."
            )

        expires_in = None
        if expires_in_keys:
            values = [
                _normalize_expires_in(raw_token[key], conversions)
                for key in expires_in_keys
            ]
            expires_in = _resolve_equal(
                values, "expires_in", expires_in_keys
            )
            if len(expires_in_keys) > 1:
                duplicates.append("expires_in aliases agree: {}".format(
                    ", ".join(expires_in_keys)
                ))
            for key in expires_in_keys:
                if key != "expires_in":
                    conversions.append("{}->expires_in".format(key))

        expires_at = None
        if expires_at_keys:
            values = [
                _normalize_expires_at(raw_token[key], evaluated_at, conversions)
                for key in expires_at_keys
            ]
            expires_at = _resolve_equal(
                values, "expires_at", expires_at_keys
            )
            if len(expires_at_keys) > 1:
                duplicates.append("expires_at aliases agree: {}".format(
                    ", ".join(expires_at_keys)
                ))
            for key in expires_at_keys:
                if key != "expires_at":
                    conversions.append("{}->expires_at".format(key))

        if expires_in is not None and expires_at is not None:
            expected = evaluated_at + expires_in
            if abs(expires_at - expected) > expiry_tolerance:
                raise TokenResponseError(
                    "expires_in and expires_at disagree by more than {} seconds."
                    .format(expiry_tolerance)
                )
        elif expires_in is not None:
            expires_at = evaluated_at + expires_in
            conversions.append("expires_in: relative -> expires_at")
        else:
            expires_in = expires_at - evaluated_at
            if expires_in <= 0:
                raise TokenResponseError("expires_at is not in the future.")
            conversions.append("expires_at: absolute -> expires_in")

        if "scope" in raw_token:
            if raw_token["scope"] is None:
                raise TokenResponseError("Response scope must not be null.")
            granted = _scope_from_response(raw_token["scope"])
        elif requested is None:
            granted = None
        else:
            granted = requested
            conversions.append("scope: absent -> requested scope")

        boundary = requested
        boundary_name = "requested authorization range"
        if (
            normalized_previous_scope is not None
            and boundary is not None
            and set(normalized_previous_scope).issubset(set(boundary))
        ):
            boundary = normalized_previous_scope
            boundary_name = "previously granted scope"

        if granted is not None:
            if boundary is None:
                if granted:
                    raise TokenResponseError(
                        "Response grants scope but no scope was requested."
                    )
            elif not set(granted).issubset(set(boundary)):
                extra = sorted(set(granted) - set(boundary))
                raise TokenResponseError(
                    "Response scope expands the {}: {}."
                    .format(boundary_name, ", ".join(extra))
                )
        normalized = {
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": expires_in,
            "expires_at": expires_at,
        }
        if refresh_token is not None:
            normalized["refresh_token"] = refresh_token
        if granted:
            normalized["scope"] = " ".join(granted)
        if granted is not None and requested is not None:
            if set(granted) != set(requested):
                conversions.append("scope: narrower grant retained")

        return TokenNormalizationAudit(
            raw_body=decoded_body,
            raw_token=raw_token,
            normalized_token=normalized,
            requested_scope=requested,
            previous_scope=normalized_previous_scope,
            granted_scope=granted,
            conversions=conversions,
            duplicate_fields=duplicates,
            unknown_fields=unknown_fields,
            status="accepted",
            operation=operation,
            evaluated_at=evaluated_at,
            expiry_tolerance=expiry_tolerance,
        )
    except TokenResponseError as exc:
        return _rejected(
            decoded_body,
            raw_token,
            normalized_requested_scope,
            str(exc),
            operation,
            evaluated_at,
            expiry_tolerance,
            unknown_fields,
            previous_scope=normalized_previous_scope,
        )


def normalize_vendor_token_response(
    raw_body,
    requested_scope=None,
    operation=None,
    now=None,
    expiry_tolerance=5,
    previous_scope=None,
):
    """Return an accepted audit or raise :class:`TokenResponseError`.

    See :func:`inspect_vendor_token_response` for the parameters.
    """
    audit = inspect_vendor_token_response(
        raw_body,
        requested_scope=requested_scope,
        operation=operation,
        now=now,
        expiry_tolerance=expiry_tolerance,
        previous_scope=previous_scope,
    )
    if audit.status == "rejected":
        raise TokenResponseError(audit.reason, audit=audit)
    return audit


def vendor_token_compliance_fix(session, clock=None, expiry_tolerance=5):
    """Attach the two-version normalizer to an :class:`OAuth2Session`.

    The adapter runs before oauthlib parses the response.  On acceptance, only
    the normalized allow-listed token is exposed to oauthlib.  On rejection,
    :class:`TokenResponseError` is raised and ``OAuth2Session`` restores the
    token state that existed before the exchange.  The latest audit record is
    always available as ``session.last_token_audit``.

    :param session: The session to modify and return.
    :param clock: Optional zero-argument callable used for expiry validation.
    :param expiry_tolerance: Allowed drift between relative and absolute
        expiry fields.
    """

    def _hook(operation):
        def _normalize_response(response):
            previous_scope = None
            if operation == "refresh_token":
                previous_scope = session.token.get("scope")
            audit = inspect_vendor_token_response(
                response.text,
                requested_scope=session.scope,
                operation=operation,
                now=clock,
                expiry_tolerance=expiry_tolerance,
                previous_scope=previous_scope,
            )
            session.last_token_audit = audit
            if audit.status == "error_response":
                return response
            if audit.status == "rejected":
                raise TokenResponseError(audit.reason, audit=audit)
            response._content = json.dumps(audit.normalized_token).encode("utf-8")
            return response

        return _normalize_response

    session.register_compliance_hook(
        "access_token_response", _hook("access_token")
    )
    session.register_compliance_hook(
        "refresh_token_response", _hook("refresh_token")
    )
    session._token_scope_validated = True
    return session
