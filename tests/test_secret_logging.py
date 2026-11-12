"""Secret-flow tests: debug logs and public exception text must never
contain access tokens, refresh tokens or client secrets.

Each class of fake credential carries a distinct marker (``MARK-...``).
The tests drive the authorization exchange, auto-refresh, OAuth 1 signing
and error paths while a real logging handler is attached at DEBUG level,
then assert that no marker reaches the log stream or formatted exceptions,
while phase, status code and target information is preserved.
"""

import io
import json
import logging
import unittest
from base64 import b64encode

import requests
from oauthlib.oauth1 import SIGNATURE_TYPE_BODY, SIGNATURE_TYPE_QUERY
from oauthlib.oauth2 import WebApplicationClient

from requests_oauthlib import OAuth1, OAuth1Session, OAuth2Session
from requests_oauthlib.oauth1_session import TokenMissing, TokenRequestDenied

CLIENT_ID = "client-id"
CLIENT_SECRET = "MARK-client-secret-4f9a2c01"
ACCESS_TOKEN = "MARK-access-token-71bd03aa2"
REFRESH_TOKEN = "MARK-refresh-token-e50a19bb3"
ROTATED = [
    "MARK-rotated-access-token-c8d2f6",
    "MARK-rotated-refresh-token-09be31",
]
OAUTH1_CLIENT_SECRET = "MARK-oauth1-client-secret-5d77aa"
OAUTH1_TOKEN = "MARK-oauth1-token-2f6c41bb5"
OAUTH1_TOKEN_SECRET = "MARK-oauth1-token-secret-83e0bd"
OAUTH1_VERIFIER = "MARK-oauth1-verifier-6a54ceff"

# Base64 of "client-id:MARK-client-secret-..." as sent in a Basic auth
# header. The marker is not visible verbatim, so it is checked separately.
BASIC_AUTH_BLOB = b64encode("{}:{}".format(CLIENT_ID, CLIENT_SECRET).encode()).decode()

ALL_MARKERS = [
    CLIENT_SECRET,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    OAUTH1_CLIENT_SECRET,
    OAUTH1_TOKEN,
    OAUTH1_TOKEN_SECRET,
    OAUTH1_VERIFIER,
    BASIC_AUTH_BLOB,
] + ROTATED


class LogCapture:
    """Attach a real StreamHandler to the package logger at DEBUG level."""

    def __init__(self):
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setFormatter(
            logging.Formatter("%(name)s:%(levelname)s:%(message)s")
        )

    def __enter__(self):
        self.logger = logging.getLogger("requests_oauthlib")
        self._previous_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)
        return self

    def __exit__(self, *exc_info):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self._previous_level)

    @property
    def text(self):
        return self.stream.getvalue()


def make_response(request, status_code=200, body="", content_type="application/json"):
    response = requests.Response()
    response.status_code = status_code
    response.headers["Content-Type"] = content_type
    response._content = body.encode("utf-8")
    response.request = request
    return response


class SecretFlowTestCase(unittest.TestCase):
    def assert_no_markers(self, text):
        for marker in ALL_MARKERS:
            self.assertNotIn(marker, text)


class OAuth2SecretFlowTest(SecretFlowTestCase):
    token_payload = {
        "token_type": "Bearer",
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "expires_in": 3600,
    }

    def make_session(self, **kwargs):
        session = OAuth2Session(
            client=WebApplicationClient(CLIENT_ID, code="code-xyz"), **kwargs
        )
        session.send = lambda request, **kw: make_response(
            request, body=json.dumps(self.token_payload)
        )
        return session

    def test_authorization_exchange(self):
        variants = (
            {"include_client_id": False},
            {"include_client_id": True},
            {"include_client_id": True, "force_querystring": True},
        )
        for kwargs in variants:
            with self.subTest(**kwargs):
                session = self.make_session()
                with LogCapture() as logs:
                    session.fetch_token(
                        "https://provider.example.com/token",
                        client_secret=CLIENT_SECRET,
                        **kwargs
                    )
                self.assert_no_markers(logs.text)
                # Safe locating information is preserved.
                self.assertIn("fetch token completed with status 200", logs.text)
                self.assertIn("https://provider.example.com/token", logs.text)
                self.assertIn("Obtained token with parameters", logs.text)

    def test_auto_refresh(self):
        rotated_payload = {
            "token_type": "Bearer",
            "access_token": ROTATED[0],
            "refresh_token": ROTATED[1],
            "expires_in": 3600,
        }
        expired_token = {
            "token_type": "Bearer",
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "expires_in": 3600,
            "expires_at": 1,
        }

        def fake_send(request, **kwargs):
            if "/refresh" in request.url:
                return make_response(request, body=json.dumps(rotated_payload))
            return make_response(request, body="{}")

        session = OAuth2Session(
            client=WebApplicationClient(CLIENT_ID),
            token=expired_token,
            auto_refresh_url="https://provider.example.com/refresh",
            auto_refresh_kwargs={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
            token_updater=lambda token: None,
        )
        session.send = fake_send
        with LogCapture() as logs:
            session.get("https://api.example.com/resource")
        self.assert_no_markers(logs.text)
        self.assertIn("Auto refresh is set", logs.text)
        self.assertIn("refresh token completed with status 200", logs.text)
        self.assertIn("https://provider.example.com/refresh", logs.text)


class OAuth1SecretFlowTest(SecretFlowTestCase):
    def test_signing(self):
        for signature_type in (None, SIGNATURE_TYPE_QUERY, SIGNATURE_TYPE_BODY):
            with self.subTest(signature_type=signature_type):
                kwargs = {}
                if signature_type:
                    kwargs["signature_type"] = signature_type
                auth = OAuth1(
                    "client-key",
                    client_secret=OAUTH1_CLIENT_SECRET,
                    resource_owner_key=OAUTH1_TOKEN,
                    resource_owner_secret=OAUTH1_TOKEN_SECRET,
                    **kwargs
                )
                prepared = requests.Request(
                    "POST",
                    "https://api.example.com/resource?foo=bar",
                    data={"a": "b"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ).prepare()
                with LogCapture() as logs:
                    auth(prepared)
                self.assert_no_markers(logs.text)
                self.assertIn("Updated url: https://api.example.com/resource", logs.text)

    def test_token_flow(self):
        body = "oauth_token={}&oauth_token_secret={}".format(
            OAUTH1_TOKEN, OAUTH1_TOKEN_SECRET
        )
        session = OAuth1Session(
            "client-key",
            client_secret=OAUTH1_CLIENT_SECRET,
            callback_uri="https://client.example.com/callback",
        )
        session.send = lambda request, **kw: make_response(
            request, body=body, content_type="application/x-www-form-urlencoded"
        )
        with LogCapture() as logs:
            session.fetch_request_token("https://provider.example.com/request-token")
            session.authorization_url("https://provider.example.com/authorize")
            session.parse_authorization_response(
                "https://client.example.com/callback"
                "?oauth_token={}&oauth_verifier={}".format(OAUTH1_TOKEN, OAUTH1_VERIFIER)
            )
            session.fetch_access_token("https://provider.example.com/access-token")
        self.assert_no_markers(logs.text)
        self.assertIn(
            "Fetching token from https://provider.example.com/request-token",
            logs.text,
        )
        self.assertIn("Decoding token from response with status 200", logs.text)
        self.assertIn(
            "Parsing token from query part of url https://client.example.com/callback",
            logs.text,
        )


class ExceptionTextTest(SecretFlowTestCase):
    def make_oauth1_session(self, status_code, body):
        session = OAuth1Session("client-key", client_secret=OAUTH1_CLIENT_SECRET)
        session.send = lambda request, **kw: make_response(
            request,
            status_code=status_code,
            body=body,
            content_type="application/x-www-form-urlencoded",
        )
        return session

    def test_token_request_denied(self):
        # Simulate a provider echoing credentials back in an error response.
        body = "error=invalid_client&echoed={}".format(OAUTH1_CLIENT_SECRET)
        session = self.make_oauth1_session(400, body)
        with LogCapture() as logs:
            with self.assertRaises(TokenRequestDenied) as cm:
                session.fetch_request_token("https://provider.example.com/request-token")
        self.assert_no_markers(str(cm.exception))
        self.assert_no_markers(logs.text)
        # Status code is preserved and the raw response remains available
        # programmatically for callers that really need it.
        self.assertIn("400", str(cm.exception))
        self.assertEqual(cm.exception.response.status_code, 400)
        self.assertIn(OAUTH1_CLIENT_SECRET, cm.exception.response.text)

    def test_token_missing(self):
        body = "oauth_token_secret={}&foo=bar".format(OAUTH1_TOKEN_SECRET)
        session = self.make_oauth1_session(200, body)
        with self.assertRaises(TokenMissing) as cm:
            session.fetch_request_token("https://provider.example.com/request-token")
        self.assert_no_markers(str(cm.exception))
        self.assertIn("oauth_token_secret", str(cm.exception))

    def test_undecodable_response(self):
        # A non urlencoded error page must not be echoed into the exception.
        body = "<html>secret={}</html>".format(OAUTH1_CLIENT_SECRET)
        session = self.make_oauth1_session(200, body)
        with self.assertRaises(ValueError) as cm:
            session.fetch_request_token("https://provider.example.com/request-token")
        self.assert_no_markers(str(cm.exception))


if __name__ == "__main__":
    unittest.main()
