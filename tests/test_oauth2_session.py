import json
import time
import tempfile
import shutil
import os
from base64 import b64encode
from copy import deepcopy
from unittest import TestCase

from unittest import mock

from oauthlib.common import urlencode, urldecode
from oauthlib.oauth2 import TokenExpiredError, OAuth2Error
from oauthlib.oauth2 import MismatchingStateError
from oauthlib.oauth2 import WebApplicationClient, MobileApplicationClient
from oauthlib.oauth2 import LegacyApplicationClient, BackendApplicationClient
from requests_oauthlib import OAuth2Session, TokenUpdated
import requests
from requests.exceptions import UnrewindableBodyError

from requests.auth import _basic_auth_str


fake_time = time.time()
CODE = "asdf345xdf"


def fake_token(token):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock()
        resp.text = json.dumps(token)
        return resp

    return fake_send


class OAuth2SessionTest(TestCase):
    def setUp(self):
        self.token = {
            "token_type": "Bearer",
            "access_token": "asdfoiw37850234lkjsdfsdf",
            "refresh_token": "sldvafkjw34509s8dfsdf",
            "expires_in": 3600,
            "expires_at": fake_time + 3600,
        }
        # use someclientid:someclientsecret to easily differentiate between client and user credentials
        # these are the values used in oauthlib tests
        self.client_id = "someclientid"
        self.client_secret = "someclientsecret"
        self.user_username = "user_username"
        self.user_password = "user_password"
        self.client_WebApplication = WebApplicationClient(self.client_id, code=CODE)
        self.client_LegacyApplication = LegacyApplicationClient(self.client_id)
        self.client_BackendApplication = BackendApplicationClient(self.client_id)
        self.client_MobileApplication = MobileApplicationClient(self.client_id)
        self.clients = [
            self.client_WebApplication,
            self.client_LegacyApplication,
            self.client_BackendApplication,
        ]
        self.all_clients = self.clients + [self.client_MobileApplication]

    def test_add_token(self):
        token = "Bearer " + self.token["access_token"]

        def verifier(r, **kwargs):
            auth_header = r.headers.get(str("Authorization"), None)
            self.assertEqual(auth_header, token)
            resp = mock.MagicMock()
            resp.cookes = []
            return resp

        for client in self.all_clients:
            sess = OAuth2Session(client=client, token=self.token)
            sess.send = verifier
            sess.get("https://i.b")

    def test_mtls(self):
        cert = (
            "testsomething.example-client.pem",
            "testsomething.example-client-key.pem",
        )

        def verifier(r, **kwargs):
            self.assertIn("cert", kwargs)
            self.assertEqual(cert, kwargs["cert"])
            self.assertIn("client_id=" + self.client_id, r.body)
            resp = mock.MagicMock()
            resp.text = json.dumps(self.token)
            return resp

        for client in self.clients:
            sess = OAuth2Session(client=client)
            sess.send = verifier

            if isinstance(client, LegacyApplicationClient):
                sess.fetch_token(
                    "https://i.b",
                    include_client_id=True,
                    cert=cert,
                    username="username1",
                    password="password1",
                )
            else:
                sess.fetch_token("https://i.b", include_client_id=True, cert=cert)

    def test_authorization_url(self):
        url = "https://example.com/authorize?foo=bar"

        web = WebApplicationClient(self.client_id)
        s = OAuth2Session(client=web)
        auth_url, state = s.authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn("response_type=code", auth_url)

        mobile = MobileApplicationClient(self.client_id)
        s = OAuth2Session(client=mobile)
        auth_url, state = s.authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn("response_type=token", auth_url)

    def test_pkce_authorization_url(self):
        url = "https://example.com/authorize?foo=bar"

        web = WebApplicationClient(self.client_id)
        s = OAuth2Session(client=web, pkce="S256")
        auth_url, state = s.authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn("response_type=code", auth_url)
        self.assertIn("code_challenge=", auth_url)
        self.assertIn("code_challenge_method=S256", auth_url)

        mobile = MobileApplicationClient(self.client_id)
        s = OAuth2Session(client=mobile, pkce="S256")
        auth_url, state = s.authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn("response_type=token", auth_url)
        self.assertIn("code_challenge=", auth_url)
        self.assertIn("code_challenge_method=S256", auth_url)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_refresh_token_request(self):
        self.expired_token = dict(self.token)
        self.expired_token["expires_in"] = "-1"
        del self.expired_token["expires_at"]

        def fake_refresh(r, **kwargs):
            if "/refresh" in r.url:
                self.assertNotIn("Authorization", r.headers)
            resp = mock.MagicMock()
            resp.text = json.dumps(self.token)
            return resp

        # No auto refresh setup
        for client in self.clients:
            sess = OAuth2Session(client=client, token=self.expired_token)
            self.assertRaises(TokenExpiredError, sess.get, "https://i.b")

        # Auto refresh but no auto update
        for client in self.clients:
            sess = OAuth2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
            )
            sess.send = fake_refresh
            self.assertRaises(TokenUpdated, sess.get, "https://i.b")

        # Auto refresh and auto update
        def token_updater(token):
            self.assertEqual(token, self.token)

        for client in self.clients:
            sess = OAuth2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
                token_updater=token_updater,
            )
            sess.send = fake_refresh
            sess.get("https://i.b")

        def fake_refresh_with_auth(r, **kwargs):
            if "/refresh" in r.url:
                self.assertIn("Authorization", r.headers)
                encoded = b64encode(
                    "{client_id}:{client_secret}".format(
                        client_id=self.client_id, client_secret=self.client_secret
                    ).encode("latin1")
                )
                content = "Basic {encoded}".format(encoded=encoded.decode("latin1"))
                self.assertEqual(r.headers["Authorization"], content)
            resp = mock.MagicMock()
            resp.text = json.dumps(self.token)
            return resp

        for client in self.clients:
            sess = OAuth2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
                token_updater=token_updater,
            )
            sess.send = fake_refresh_with_auth
            sess.get(
                "https://i.b",
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

    @mock.patch("time.time", new=lambda: fake_time)
    def test_token_from_fragment(self):
        mobile = MobileApplicationClient(self.client_id)
        response_url = "https://i.b/callback#" + urlencode(self.token.items())
        sess = OAuth2Session(client=mobile)
        self.assertEqual(sess.token_from_fragment(response_url), self.token)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_fetch_token(self):
        url = "https://example.com/token"

        for client in self.clients:
            sess = OAuth2Session(client=client, token=self.token)
            sess.send = fake_token(self.token)
            if isinstance(client, LegacyApplicationClient):
                # this client requires a username+password
                # if unset, an error will be raised
                self.assertRaises(ValueError, sess.fetch_token, url)
                self.assertRaises(
                    ValueError, sess.fetch_token, url, username="username1"
                )
                self.assertRaises(
                    ValueError, sess.fetch_token, url, password="password1"
                )
                # otherwise it will pass
                self.assertEqual(
                    sess.fetch_token(url, username="username1", password="password1"),
                    self.token,
                )
            else:
                self.assertEqual(sess.fetch_token(url), self.token)

        error = {"error": "invalid_request"}
        for client in self.clients:
            sess = OAuth2Session(client=client, token=self.token)
            sess.send = fake_token(error)
            if isinstance(client, LegacyApplicationClient):
                # this client requires a username+password
                # if unset, an error will be raised
                self.assertRaises(ValueError, sess.fetch_token, url)
                self.assertRaises(
                    ValueError, sess.fetch_token, url, username="username1"
                )
                self.assertRaises(
                    ValueError, sess.fetch_token, url, password="password1"
                )
                # otherwise it will pass
                self.assertRaises(
                    OAuth2Error,
                    sess.fetch_token,
                    url,
                    username="username1",
                    password="password1",
                )
            else:
                self.assertRaises(OAuth2Error, sess.fetch_token, url)

        # there are different scenarios in which the `client_id` can be specified
        # reference `oauthlib.tests.oauth2.rfc6749.clients.test_web_application.WebApplicationClientTest.test_prepare_request_body`
        # this only needs to test WebApplicationClient
        client = self.client_WebApplication
        client.tester = True

        # this should be a tuple of (r.url, r.body, r.headers.get('Authorization'))
        _fetch_history = []

        def fake_token_history(token):
            def fake_send(r, **kwargs):
                resp = mock.MagicMock()
                resp.text = json.dumps(token)
                _fetch_history.append(
                    (r.url, r.body, r.headers.get("Authorization", None))
                )
                return resp

            return fake_send

        sess = OAuth2Session(client=client, token=self.token)
        sess.send = fake_token_history(self.token)
        expected_auth_header = _basic_auth_str(self.client_id, self.client_secret)

        # scenario 1 - default request
        # this should send the `client_id` in the headers, as that is recommended by the RFC
        self.assertEqual(
            sess.fetch_token(url, client_secret="someclientsecret"), self.token
        )
        self.assertEqual(len(_fetch_history), 1)
        self.assertNotIn(
            "client_id", _fetch_history[0][1]
        )  # no `client_id` in the body
        self.assertNotIn(
            "client_secret", _fetch_history[0][1]
        )  # no `client_secret` in the body
        self.assertEqual(
            _fetch_history[0][2], expected_auth_header
        )  # ensure a Basic Authorization header

        # scenario 2 - force the `client_id` into the body
        self.assertEqual(
            sess.fetch_token(
                url, client_secret="someclientsecret", include_client_id=True
            ),
            self.token,
        )
        self.assertEqual(len(_fetch_history), 2)
        self.assertIn("client_id=%s" % self.client_id, _fetch_history[1][1])
        self.assertIn("client_secret=%s" % self.client_secret, _fetch_history[1][1])
        self.assertEqual(
            _fetch_history[1][2], None
        )  # ensure NO Basic Authorization header

        # scenario 3 - send in an auth object
        auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)
        self.assertEqual(sess.fetch_token(url, auth=auth), self.token)
        self.assertEqual(len(_fetch_history), 3)
        self.assertNotIn(
            "client_id", _fetch_history[2][1]
        )  # no `client_id` in the body
        self.assertNotIn(
            "client_secret", _fetch_history[2][1]
        )  # no `client_secret` in the body
        self.assertEqual(
            _fetch_history[2][2], expected_auth_header
        )  # ensure a Basic Authorization header

        # scenario 4 - send in a username/password combo
        # this should send the `client_id` in the headers, like scenario 1
        self.assertEqual(
            sess.fetch_token(
                url, username=self.user_username, password=self.user_password
            ),
            self.token,
        )
        self.assertEqual(len(_fetch_history), 4)
        self.assertNotIn(
            "client_id", _fetch_history[3][1]
        )  # no `client_id` in the body
        self.assertNotIn(
            "client_secret", _fetch_history[3][1]
        )  # no `client_secret` in the body
        self.assertEqual(
            _fetch_history[0][2], expected_auth_header
        )  # ensure a Basic Authorization header
        self.assertIn("username=%s" % self.user_username, _fetch_history[3][1])
        self.assertIn("password=%s" % self.user_password, _fetch_history[3][1])

        # scenario 5 - send data in `params` and not in `data` for providers
        # that expect data in URL
        self.assertEqual(
            sess.fetch_token(url, client_secret="somesecret", force_querystring=True),
            self.token,
        )
        self.assertIn("code=%s" % CODE, _fetch_history[4][0])

        # some quick tests for valid ways of supporting `client_secret`

        # scenario 2b - force the `client_id` into the body; but the `client_secret` is `None`
        self.assertEqual(
            sess.fetch_token(url, client_secret=None, include_client_id=True),
            self.token,
        )
        self.assertEqual(len(_fetch_history), 6)
        self.assertIn("client_id=%s" % self.client_id, _fetch_history[5][1])
        self.assertNotIn(
            "client_secret=", _fetch_history[5][1]
        )  # no `client_secret` in the body
        self.assertEqual(
            _fetch_history[5][2], None
        )  # ensure NO Basic Authorization header

        # scenario 2c - force the `client_id` into the body; but the `client_secret` is an empty string
        self.assertEqual(
            sess.fetch_token(url, client_secret="", include_client_id=True), self.token
        )
        self.assertEqual(len(_fetch_history), 7)
        self.assertIn("client_id=%s" % self.client_id, _fetch_history[6][1])
        self.assertIn("client_secret=", _fetch_history[6][1])
        self.assertEqual(
            _fetch_history[6][2], None
        )  # ensure NO Basic Authorization header

    def test_cleans_previous_token_before_fetching_new_one(self):
        """Makes sure the previous token is cleaned before fetching a new one.

        The reason behind it is that, if the previous token is expired, this
        method shouldn't fail with a TokenExpiredError, since it's attempting
        to get a new one (which shouldn't be expired).

        """
        new_token = deepcopy(self.token)
        past = time.time() - 7200
        now = time.time()
        self.token["expires_at"] = past
        new_token["expires_at"] = now + 3600
        url = "https://example.com/token"

        with mock.patch("time.time", lambda: now):
            for client in self.clients:
                sess = OAuth2Session(client=client, token=self.token)
                sess.send = fake_token(new_token)
                if isinstance(client, LegacyApplicationClient):
                    # this client requires a username+password
                    # if unset, an error will be raised
                    self.assertRaises(ValueError, sess.fetch_token, url)
                    self.assertRaises(
                        ValueError, sess.fetch_token, url, username="username1"
                    )
                    self.assertRaises(
                        ValueError, sess.fetch_token, url, password="password1"
                    )
                    # otherwise it will pass
                    self.assertEqual(
                        sess.fetch_token(
                            url, username="username1", password="password1"
                        ),
                        new_token,
                    )
                else:
                    self.assertEqual(sess.fetch_token(url), new_token)

    def test_web_app_fetch_token(self):
        # Ensure the state parameter is used, see issue #105.
        client = OAuth2Session("someclientid", state="somestate")
        self.assertRaises(
            MismatchingStateError,
            client.fetch_token,
            "https://i.b/token",
            authorization_response="https://i.b/no-state?code=abc",
        )

    @mock.patch("time.time", new=lambda: fake_time)
    def test_pkce_web_app_fetch_token(self):
        url = "https://example.com/token"

        web = WebApplicationClient(self.client_id, code=CODE)
        sess = OAuth2Session(client=web, token=self.token, pkce="S256")
        sess.send = fake_token(self.token)
        sess._code_verifier = "foobar"
        self.assertEqual(sess.fetch_token(url), self.token)

    def test_client_id_proxy(self):
        sess = OAuth2Session("test-id")
        self.assertEqual(sess.client_id, "test-id")
        sess.client_id = "different-id"
        self.assertEqual(sess.client_id, "different-id")
        sess._client.client_id = "something-else"
        self.assertEqual(sess.client_id, "something-else")
        del sess.client_id
        self.assertIsNone(sess.client_id)

    def test_access_token_proxy(self):
        sess = OAuth2Session("test-id")
        self.assertIsNone(sess.access_token)
        sess.access_token = "test-token"
        self.assertEqual(sess.access_token, "test-token")
        sess._client.access_token = "different-token"
        self.assertEqual(sess.access_token, "different-token")
        del sess.access_token
        self.assertIsNone(sess.access_token)

    def test_token_proxy(self):
        token = {"access_token": "test-access"}
        sess = OAuth2Session("test-id", token=token)
        self.assertEqual(sess.access_token, "test-access")
        self.assertEqual(sess.token, token)
        token["access_token"] = "something-else"
        sess.token = token
        self.assertEqual(sess.access_token, "something-else")
        self.assertEqual(sess.token, token)
        sess._client.access_token = "different-token"
        token["access_token"] = "different-token"
        self.assertEqual(sess.access_token, "different-token")
        self.assertEqual(sess.token, token)
        # can't delete token attribute
        with self.assertRaises(AttributeError):
            del sess.token

    def test_authorized_false(self):
        sess = OAuth2Session("someclientid")
        self.assertFalse(sess.authorized)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_authorized_true(self):
        def fake_token(token):
            def fake_send(r, **kwargs):
                resp = mock.MagicMock()
                resp.text = json.dumps(token)
                return resp

            return fake_send

        url = "https://example.com/token"

        for client in self.clients:
            sess = OAuth2Session(client=client)
            sess.send = fake_token(self.token)
            self.assertFalse(sess.authorized)
            if isinstance(client, LegacyApplicationClient):
                # this client requires a username+password
                # if unset, an error will be raised
                self.assertRaises(ValueError, sess.fetch_token, url)
                self.assertRaises(
                    ValueError, sess.fetch_token, url, username="username1"
                )
                self.assertRaises(
                    ValueError, sess.fetch_token, url, password="password1"
                )
                # otherwise it will pass
                sess.fetch_token(url, username="username1", password="password1")
            else:
                sess.fetch_token(url)
            self.assertTrue(sess.authorized)


class CountingStream:
    """A file-like object that records how often and from where it is read."""

    def __init__(self, content):
        self._content = content
        self._position = 0
        self.reads = []
        self.seeks = []

    def read(self, size=-1):
        self.reads.append(self._position)
        if size is None or size < 0:
            size = len(self._content) - self._position
        chunk = self._content[self._position : self._position + size]
        self._position += len(chunk)
        return chunk

    def tell(self):
        return self._position

    def seek(self, position, whence=0):
        self.seeks.append((position, whence))
        if whence == 0:
            self._position = position
        elif whence == 1:
            self._position += position
        else:
            self._position = len(self._content) + position
        return self._position


class UnrewindableStream(CountingStream):
    def seek(self, position, whence=0):
        self.seeks.append((position, whence))
        raise OSError("stream is not seekable")


class OAuth2UploadRefreshTest(TestCase):
    """Uploads must keep their body ownership across an automatic refresh."""

    client_id = "someclientid"
    client_secret = "someclientsecret"

    def setUp(self):
        self.expired_token = {
            "token_type": "Bearer",
            "access_token": "expired-access-token",
            "refresh_token": "refresh-token",
            "expires_in": "-1",
            "expires_at": time.time() - 10,
        }
        self.fresh_token = {
            "token_type": "Bearer",
            "access_token": "fresh-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "expires_at": time.time() + 3600,
        }

    def _session(self, refresh_response=None, token_updater=None):
        session = OAuth2Session(
            client_id=self.client_id,
            token=dict(self.expired_token),
            auto_refresh_url="https://token.example/refresh",
            token_updater=token_updater
            if token_updater is not None
            else (lambda t: None),
        )
        session.requests = []

        def fake_send(prepared, **kwargs):
            session.requests.append(prepared)
            response = mock.MagicMock()
            response.status_code = 200
            if prepared.url.startswith("https://token.example/refresh"):
                response.text = json.dumps(
                    self.fresh_token if refresh_response is None else refresh_response
                )
            else:
                response.text = "ok"
            return response

        session.send = fake_send
        return session

    def _payload(self, session):
        token_requests = [
            r for r in session.requests if r.url.startswith("https://token.example/")
        ]
        resource_requests = [
            r
            for r in session.requests
            if not r.url.startswith("https://token.example/")
        ]
        return token_requests, resource_requests

    def test_refresh_receives_only_token_parameters(self):
        session = self._session()
        uploaded = CountingStream(b"binary-payload")

        session.post(
            "https://api.example/upload?resource=1",
            data={"description": "hello"},
            files={"file": ("data.bin", uploaded)},
            headers={"X-Resource-Header": "resource-only"},
            params={"tenant": "resource-only"},
            json={"ignored": "resource-only"},
            allow_redirects=False,
            stream=True,
            hooks={"response": []},
            auth=("client", "secret"),
        )

        token_requests, resource_requests = self._payload(session)
        self.assertEqual(len(token_requests), 1)
        self.assertEqual(len(resource_requests), 1)

        token_request = token_requests[0]
        token_body = token_request.body
        if isinstance(token_body, bytes):
            token_body = token_body.decode("utf-8")
        token_params = dict(urldecode(token_body))
        self.assertEqual(token_params["grant_type"], "refresh_token")
        self.assertEqual(token_params["refresh_token"], "refresh-token")
        for leaked in (
            "description",
            "json",
            "params",
            "stream",
            "allow_redirects",
            "hooks",
            "tenant",
        ):
            self.assertNotIn(leaked, token_params)
        self.assertNotIn("X-Resource-Header", token_request.headers)

        resource_request = resource_requests[0]
        self.assertIn("tenant=resource-only", resource_request.url)
        self.assertEqual(
            resource_request.headers["Authorization"],
            "Bearer fresh-access-token",
        )
        self.assertEqual(resource_request.headers["X-Resource-Header"], "resource-only")

    def test_refresh_does_not_read_upload_stream(self):
        session = self._session()
        uploaded = CountingStream(b"binary-payload")

        session.post(
            "https://api.example/upload",
            files={"file": ("data.bin", uploaded)},
        )

        _, resource_requests = self._payload(session)
        self.assertEqual(len(resource_requests), 1)
        # Exactly one read, by requests when building the multipart body.
        self.assertEqual(len(uploaded.reads), 1)
        self.assertEqual(uploaded.reads[0], 0)
        self.assertIn(b"binary-payload", resource_requests[0].body)

    def test_refresh_restores_stream_before_second_send(self):
        session = self._session()
        uploaded = CountingStream(b"binary-payload")

        session.post(
            "https://api.example/upload",
            files={"file": ("data.bin", uploaded)},
        )

        # The refresh must not consume the stream, so its position is still
        # at the original offset when the business request is built.
        self.assertEqual(uploaded.seeks, [])
        _, resource_requests = self._payload(session)
        self.assertEqual(len(resource_requests), 1)

    def test_refresh_failure_leaves_body_untouched(self):
        session = self._session(refresh_response={"error": "invalid_grant"})
        uploaded = CountingStream(b"binary-payload")

        with self.assertRaises(OAuth2Error):
            session.post(
                "https://api.example/upload",
                files={"file": ("data.bin", uploaded)},
            )

        self.assertEqual(uploaded.reads, [])
        self.assertEqual(uploaded.tell(), 0)
        token_requests, resource_requests = self._payload(session)
        self.assertEqual(len(token_requests), 1)
        self.assertEqual(resource_requests, [])

    def test_token_updated_allows_caller_to_retry(self):
        session = self._session(token_updater=None)
        session.token_updater = None
        uploaded = CountingStream(b"binary-payload")

        with self.assertRaises(TokenUpdated) as raised:
            session.post(
                "https://api.example/upload",
                files={"file": ("data.bin", uploaded)},
            )

        self.assertEqual(raised.exception.token["access_token"], "fresh-access-token")
        self.assertEqual(uploaded.reads, [])
        _, resource_requests = self._payload(session)
        self.assertEqual(resource_requests, [])

        # The caller can retry with the refreshed token and the same stream.
        session.token = raised.exception.token
        session.token_updater = lambda token: None
        session.post(
            "https://api.example/upload",
            files={"file": ("data.bin", uploaded)},
        )
        token_requests, resource_requests = self._payload(session)
        self.assertEqual(len(token_requests), 1)
        self.assertEqual(len(resource_requests), 1)
        self.assertIn(b"binary-payload", resource_requests[0].body)

    def test_unrewindable_stream_raises_instead_of_sending_truncated_body(self):
        session = self._session()
        uploaded = UnrewindableStream(b"binary-payload")

        def consuming_hook(url, headers, data):
            uploaded.read()
            return url, headers, data

        session.register_compliance_hook("protected_request", consuming_hook)

        with self.assertRaises(UnrewindableBodyError):
            session.post(
                "https://api.example/upload",
                files={"file": ("data.bin", uploaded)},
            )

        _, resource_requests = self._payload(session)
        self.assertEqual(resource_requests, [])
        self.assertEqual(uploaded.reads, [0])

    def test_unrewindable_stream_after_successful_refresh_is_reported(self):
        session = self._session()
        uploaded = UnrewindableStream(b"binary-payload")

        def consuming_refresh_hook(url, headers, body):
            uploaded.read()
            return url, headers, body

        session.register_compliance_hook(
            "refresh_token_request", consuming_refresh_hook
        )

        with self.assertRaises(UnrewindableBodyError):
            session.post(
                "https://api.example/upload",
                files={"file": ("data.bin", uploaded)},
            )

        token_requests, resource_requests = self._payload(session)
        self.assertEqual(len(token_requests), 1)
        self.assertEqual(resource_requests, [])
        self.assertEqual(uploaded.reads, [0])

    def test_data_stream_is_not_replayed_into_token_request(self):
        session = self._session()
        uploaded = CountingStream(b"raw-payload")

        session.put("https://api.example/upload", data=uploaded)

        token_requests, resource_requests = self._payload(session)
        self.assertEqual(len(token_requests), 1)
        self.assertEqual(len(resource_requests), 1)
        self.assertEqual(uploaded.reads, [])
        self.assertIs(resource_requests[0].body, uploaded)


class OAuth2SessionNetrcTest(OAuth2SessionTest):
    """Ensure that there is no magic auth handling.

    By default, requests sessions have magic handling of netrc files,
    which is undesirable for this library because it will take
    precedence over manually set authentication headers.
    """

    def setUp(self):
        # Set up a temporary home directory
        self.homedir = tempfile.mkdtemp()
        self.prehome = os.environ.get("HOME", None)
        os.environ["HOME"] = self.homedir

        # Write a .netrc file that will cause problems
        netrc_loc = os.path.expanduser("~/.netrc")
        with open(netrc_loc, "w") as f:
            f.write("machine i.b\n" "  password abc123\n" "  login spam@eggs.co\n")

        super(OAuth2SessionNetrcTest, self).setUp()

    def tearDown(self):
        super(OAuth2SessionNetrcTest, self).tearDown()

        if self.prehome is not None:
            os.environ["HOME"] = self.prehome
        shutil.rmtree(self.homedir)
