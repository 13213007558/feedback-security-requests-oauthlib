Token response normalization and validation
==========================================

This page describes the compatibility boundary for a provider that serves
two versions of its OAuth 2 token response.  The implementation lives in
``requests_oauthlib/token_normalization.py``; it is independent of
``OAuth2Session`` and can be audited or tested on its own.

Two versions, one canonical token
---------------------------------

The legacy response uses snake_case fields and a relative lifetime.  The
current response uses camelCase fields and either a relative or an absolute
lifetime.  Both are normalized into the canonical oauthlib shape before
``OAuth2Session`` sees them.

Approved conversions
--------------------

Only the following conversions are approved.  Anything not listed here is not
a compatibility fix and must be treated as an unknown field.

Field names
~~~~~~~~~~~

======================================  ====================================
Source                                  Canonical
======================================  ====================================
``accessToken``                         ``access_token``
``refreshToken``                        ``refresh_token``
``tokenType``                           ``token_type``
``expiresIn``                           ``expires_in``
``expiresAt``                           ``expires_at``
======================================  ====================================

The snake_case spelling of each canonical field is accepted as well.  If both
spellings of the same field are present, their values must be identical after
conversion; a conflict rejects the whole response.

Token type
~~~~~~~~~~

``bearer`` and ``Bearer`` (case-insensitive) normalize to ``Bearer``.  ``mac``
and ``MAC`` normalize to ``MAC``.  ``token_type`` is never defaulted.  A
missing or unsupported token type rejects the response, because an unknown
type is not an authorization the client understands.

Expiry
~~~~~~

- ``expires_in`` accepts a positive integer, an integral float, or a string of
  decimal digits.  Zero, negative values, booleans, and non-numeric strings
  are rejected.
- ``expires_at`` accepts an integer or finite float Unix timestamp, a string of
  decimal digits, or a timezone-aware ISO-8601 timestamp.  Timestamps that are
  not in the future are rejected; timezone-free ISO-8601 strings are rejected
  because their meaning depends on an unstated timezone.
- If only ``expires_in`` is present, ``expires_at`` is derived as
  ``evaluation time + expires_in``.
- If only ``expires_at`` is present, ``expires_in`` is derived from it.
- If both are present, they must agree within ``expiry_tolerance`` seconds
  (default ``5``).  Disagreement rejects the response.
- At least one of the two fields must be present.  A token with no lifetime
  information is not trusted.

Scope
~~~~~

The scope requested during authorization is the authorization range.  The
response's ``scope`` is the grant.  For a refresh, the scope already granted
to the token being replaced is an additional upper bound: a refresh cannot
recover a scope that was requested during authorization but never granted.

- A grant that is a subset of the requested range is accepted and retained.
- A grant that adds any scope outside the requested range is rejected.  The
  error names the expanded scopes.
- If the response omits ``scope``, the requested range is used, per RFC 6749
  section 5.1, and the conversion is recorded.
- If the response supplies a scope but the client requested no scope, the
  response is rejected.  The adapter does not invent an authorization range
  from provider data.
- ``null`` is not a valid scope value.

Explicitly not approved
-----------------------

- Unknown fields are never copied into the normalized token, never used to
  widen scope, and never interpreted as roles or permissions.  They are
  preserved in the audit record under ``unknown_fields`` for review only.
- Provider-supplied ``scope`` never expands the client's requested range.
- A missing ``token_type`` is never filled in as ``Bearer``.
- An unknown token type is never coerced to ``Bearer``.
- A missing lifetime is never replaced with a default.
- A response containing both ``error`` and token material is rejected rather
  than resolved in either direction.

Reviewing a decision
--------------------

Every response handled by the adapter produces a
:class:`~requests_oauthlib.token_normalization.TokenNormalizationAudit`
record.  It links:

- ``raw_body``: the exact response body before any modification.
- ``raw_token``: the parsed original object, including unknown fields.
- ``normalized_token``: the allow-listed token oauthlib receives; ``None``
  when rejected.
- ``requested_scope``, ``previous_scope``, and ``granted_scope``: the
  authorization range, the grant being replaced, and the new grant, as ordered
  tuples.
- ``conversions``: every approved transformation that was applied.
- ``duplicate_fields``: aliases that were present and agreed.
- ``unknown_fields``: fields that were quarantined.
- ``status`` and ``reason``: ``accepted``, ``rejected``, or
  ``error_response``.

On session integration the latest record is ``session.last_token_audit`` and
``audit.to_dict()`` is JSON-serializable for logs.  A rejection raises
:class:`~requests_oauthlib.token_normalization.TokenResponseError`, whose
``audit`` attribute points at the same record.

State preservation on failure
-----------------------------

``OAuth2Session.fetch_token`` and ``OAuth2Session.refresh_token`` snapshot all
token-bearing client attributes before an exchange and restore them on any
exception.  A failed normalization, an error response, or an oauthlib parsing
error therefore leaves the previously valid token, access token, refresh token,
token type, and expiry exactly as they were.  The rejected audit record is
retained so the failure remains reviewable.

Using the adapter
-----------------

.. code-block:: python

    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.token_normalization import (
        TokenResponseError,
        vendor_token_compliance_fix,
    )

    session = OAuth2Session(client_id, scope=["read", "write"])
    session = vendor_token_compliance_fix(session)

    try:
        token = session.fetch_token(token_url, client_secret=client_secret)
    except TokenResponseError as error:
        audit = error.audit
        log.warning("token rejected: %s", audit.to_dict())

For offline verification use :func:`inspect_vendor_token_response` with a
fixed response body and ``now`` value; it returns an audit instead of raising.

Migration notes
---------------

- Existing integrations that relied on a missing ``token_type`` becoming
  ``Bearer`` must send or agree on a token type with the provider.
- Existing integrations that relied on ``expires_in: 0`` being replaced by
  ``3600`` must request a real lifetime; zero is now rejected.
- A provider that returns an absolute ``expires_at`` with a different clock
  skew than the client should be aligned, or ``expiry_tolerance`` should be
  raised deliberately after review.
- A provider that grants more scope than requested must have its authorization
  request updated to include the intended scopes; the token response cannot
  widen the session's authorization on its own.
- If a refresh legitimately needs a wider grant, the client must start a new
  authorization flow rather than expecting the refresh response to widen it.
- Responses that legitimately need new fields should add them to an explicit
  conversion rule after review, not rely on passthrough.
