# -*- coding: utf-8 -*-
"""Interface prototype: opt-in body integrity for OAuth1, failing closed.

Design rules encoded here:

* ``BodyIntegrity.NONE`` keeps today's behavior byte-for-byte.
* ``BodyIntegrity.OAUTH_BODY_HASH`` requires *explicit* peer confirmation
  (``peer_supports_body_hash=True``).  The oauth_body_hash parameter comes
  from draft-eaton-oauth-bodyhash-00, an expired Internet-Draft -- not an
  RFC -- and stock oauthlib servers never verify it, so emitting it without
  a confirmed peer would be security theater.  Refuse to build the client.
* Form-encoded bodies need no hash (parameters already enter the RFC 5849
  base string) and the draft forbids hashing them: allowed as-is.
* Binary (non-UTF-8) bodies cannot even be signed by oauthlib today
  (``to_unicode`` decodes the body as UTF-8 and raises): rejected eagerly
  at request time instead of crashing mid-signing.

Run:  .venv/bin/python analysis/oauth1_body_integrity_prototype.py
"""
import enum

from requests_oauthlib import OAuth1
from requests_oauthlib.oauth1_auth import CONTENT_TYPE_FORM_URLENCODED


class BodyIntegrity(enum.Enum):
    NONE = "none"
    OAUTH_BODY_HASH = "oauth_body_hash"  # draft-eaton-oauth-bodyhash-00 (SHA-1)


class UnsupportedBodyCombinationError(TypeError):
    """Raised when body integrity was requested for an unsupported combo."""


class OAuth1WithBodyIntegrity(OAuth1):
    def __init__(self, *args, body_integrity=BodyIntegrity.NONE,
                 peer_supports_body_hash=False, **kwargs):
        if not isinstance(body_integrity, BodyIntegrity):
            raise UnsupportedBodyCombinationError(
                f"unknown body_integrity={body_integrity!r}; "
                f"supported: {[b.value for b in BodyIntegrity]}")
        if body_integrity is BodyIntegrity.OAUTH_BODY_HASH:
            if not peer_supports_body_hash:
                raise UnsupportedBodyCombinationError(
                    "oauth_body_hash is a draft extension that stock "
                    "oauthlib servers do not verify; pass "
                    "peer_supports_body_hash=True only after the resource "
                    "server confirms it enforces draft-eaton-oauth-bodyhash-00")
            kwargs["force_include_body"] = True
        self.body_integrity = body_integrity
        super().__init__(*args, **kwargs)

    def __call__(self, r):
        if self.body_integrity is BodyIntegrity.OAUTH_BODY_HASH:
            content_type = r.headers.get("Content-Type", "")
            if isinstance(content_type, bytes):
                content_type = content_type.decode("utf-8")
            is_form = CONTENT_TYPE_FORM_URLENCODED in content_type
            if not is_form and r.body is not None:
                if isinstance(r.body, bytes):
                    try:
                        r.body.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise UnsupportedBodyCombinationError(
                            "oauth_body_hash cannot protect non-UTF-8 binary "
                            "bodies with this stack (oauthlib decodes the "
                            "body as UTF-8 before hashing); use a text-safe "
                            "encoding such as base64, or negotiate a "
                            "different integrity scheme") from exc
        return super().__call__(r)


if __name__ == "__main__":
    import json
    import requests

    CREDS = dict(client_key="k", client_secret="s",
                 resource_owner_key="t", resource_owner_secret="ts")

    def build(**kw):
        return OAuth1WithBodyIntegrity(**CREDS, **kw)

    # 1. default behavior unchanged
    build()

    # 2. integrity requested without confirmed peer -> refused
    try:
        build(body_integrity=BodyIntegrity.OAUTH_BODY_HASH)
    except UnsupportedBodyCombinationError as exc:
        print("refused (no confirmed peer):", exc)

    # 3. confirmed peer + JSON body -> signs, header carries oauth_body_hash
    auth = build(body_integrity=BodyIntegrity.OAUTH_BODY_HASH,
                 peer_supports_body_hash=True)
    p = requests.Request("POST", "http://example.com/x",
                         json={"enabled": False}, auth=auth).prepare()
    header = p.headers["Authorization"]
    if isinstance(header, bytes):
        header = header.decode()
    print("JSON signed, oauth_body_hash present:",
          "oauth_body_hash" in header)

    # 4. confirmed peer + form body -> allowed, no hash (draft 4.1.1)
    p = requests.Request("POST", "http://example.com/x",
                         data={"a": "1"}, auth=auth).prepare()
    header = p.headers["Authorization"]
    if isinstance(header, bytes):
        header = header.decode()
    print("form signed, oauth_body_hash absent:", "oauth_body_hash" not in header)

    # 5. confirmed peer + binary body -> refused at request time
    req = requests.Request("POST", "http://example.com/x",
                           data=b"\x89PNG\xff\xfe", auth=auth,
                           headers={"Content-Type": "application/octet-stream"})
    try:
        req.prepare()
    except UnsupportedBodyCombinationError as exc:
        print("refused (binary body):", exc)
