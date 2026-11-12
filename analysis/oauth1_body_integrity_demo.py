# -*- coding: utf-8 -*-
"""Evidence: does an OAuth1 (RFC 5849) signature protect the request body?

Local verification double
-------------------------
``verify_like_server`` plays the resource server: it rebuilds the signature
base string from the *received* method/URI/headers/body per RFC 5849
section 3.4.1 (body parameters only when Content-Type is
application/x-www-form-urlencoded) and recomputes HMAC-SHA1 with the shared
secrets.  ``require_body_hash=True`` additionally enforces the
draft-eaton-oauth-bodyhash-00 ``oauth_body_hash`` extension -- note stock
oauthlib servers never check it (the string only exists in client-side
``get_oauth_params``), so the default mode mirrors a stock oauthlib server.

Run:  .venv/bin/python analysis/oauth1_body_integrity_demo.py
"""
import base64
import hashlib
import hmac
import json
import re
import sys
from urllib.parse import unquote, urlparse

import requests
from oauthlib.oauth1.rfc5849 import signature
from oauthlib.oauth1.rfc5849.utils import escape
from requests_oauthlib import OAuth1

CLIENT_KEY = "dpf43f3p2l4k3l03"
CLIENT_SECRET = "kd94hf93k423kf44"
TOKEN = "nnch734d00sl2jdk"
TOKEN_SECRET = "pfkkdhi9sl3r4s00"
URL = "http://example.com/admin/config"
FORM = "application/x-www-form-urlencoded"

AUTH_PARAM_RE = re.compile(r'([a-zA-Z_]+)="([^"]*)"')


def oauth_params_of(prepped):
    header = prepped.headers.get("Authorization", b"")
    if isinstance(header, bytes):
        header = header.decode("utf-8")
    return dict(AUTH_PARAM_RE.findall(header))


def as_text(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def as_bytes(value):
    return value.encode("utf-8") if isinstance(value, str) else value


def verify_like_server(prepped, body, require_body_hash=False):
    """Verification double: verify the *received* request, not the sent one."""
    headers = {as_text(k): as_text(v) for k, v in prepped.headers.items()}
    content_type = headers.get("Content-Type", "")
    # RFC 5849 3.4.1.3.1: entity-body params only for form-urlencoded bodies.
    body_for_base_string = as_text(body) if FORM in content_type else None
    collected = signature.collect_parameters(
        uri_query=urlparse(prepped.url).query,
        body=body_for_base_string,
        headers=headers,
    )
    base_string = signature.signature_base_string(
        prepped.method,
        signature.base_string_uri(prepped.url),
        signature.normalize_parameters(collected),
    )
    key = f"{escape(CLIENT_SECRET)}&{escape(TOKEN_SECRET)}"
    digest = hmac.new(key.encode(), base_string.encode(), hashlib.sha1).digest()
    expected = base64.b64encode(digest).decode()
    sent = unquote(oauth_params_of(prepped).get("oauth_signature", ""))
    if not hmac.compare_digest(expected, sent):
        return False
    if require_body_hash:
        sent_hash = unquote(oauth_params_of(prepped).get("oauth_body_hash") or "")
        if not sent_hash:
            sent_hash = None
        if sent_hash is None:
            return False  # policy: hash mandatory for non-form bodies
        actual = base64.b64encode(
            hashlib.sha1(as_bytes(body)).digest()  # noqa: S324 - draft mandates SHA-1
        ).decode()
        return hmac.compare_digest(sent_hash, actual)
    return True


def prepare(body_kwarg, force_include_body=False, content_type=None):
    auth = OAuth1(
        CLIENT_KEY,
        client_secret=CLIENT_SECRET,
        resource_owner_key=TOKEN,
        resource_owner_secret=TOKEN_SECRET,
        force_include_body=force_include_body,
    )
    req = requests.Request("POST", URL, auth=auth, **body_kwarg)
    prepped = req.prepare()
    if content_type:
        prepped.headers["Content-Type"] = content_type
        prepped = auth(prepped)  # re-sign with final content-type
    return prepped


def scenario(title, prepped, swapped_body, require_body_hash=False):
    original_ok = verify_like_server(prepped, prepped.body, require_body_hash)
    swapped_ok = verify_like_server(prepped, swapped_body, require_body_hash)
    print(f"\n== {title} ==")
    print(f"  oauth_body_hash in header : "
          f"{oauth_params_of(prepped).get('oauth_body_hash')!r}")
    print(f"  original body verifies    : {original_ok}")
    print(f"  swapped  body verifies    : {swapped_ok}"
          f"   <-- {'PROTECTED' if not swapped_ok else 'NOT PROTECTED'}")
    return original_ok, swapped_ok


def main():
    print("oauthlib client signs; local double verifies the *received* request")

    form = prepare({"data": {"status": "hello"}})
    scenario("form-urlencoded body (default)", form, "status=pwned")

    js = prepare({"json": {"enabled": False}})
    scenario("JSON body (default)", js,
             json.dumps({"enabled": True, "role": "admin"}))

    binary = prepare({"data": b"\x89PNG\r\n\x1a\noriginal"},
                     content_type="application/octet-stream")
    scenario("binary body (default)", binary, b"\x89PNG\r\n\x1a\nREPLACED")

    js_forced = prepare({"json": {"enabled": False}}, force_include_body=True)
    scenario("JSON, force_include_body=True, signature-only verifier "
             "(= stock oauthlib server)", js_forced,
             json.dumps({"enabled": True, "role": "admin"}))
    scenario("JSON, force_include_body=True, strict verifier enforcing "
             "oauth_body_hash (draft extension)", js_forced,
             json.dumps({"enabled": True, "role": "admin"}),
             require_body_hash=True)

    print("\n== binary body, force_include_body=True ==")
    try:
        prepare({"data": b"\x89PNG\r\n\x1a\n\xff\xfe binary"},
                content_type="application/octet-stream",
                force_include_body=True)
    except Exception as exc:  # noqa: BLE001 - evidence, not API
        print(f"  signing raised {type(exc).__name__}: {exc}")

    form_forced = prepare({"data": {"status": "hello"}},
                          force_include_body=True)
    scenario("form body, force_include_body=True (hash must stay absent "
             "per draft 4.1.1)", form_forced, "status=pwned")


if __name__ == "__main__":
    sys.exit(main())
