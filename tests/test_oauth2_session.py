import json
import time
import tempfile
import shutil
import os
from base64 import b64encode
from copy import deepcopy
from unittest import TestCase

from unittest import mock

from oauthlib.common import urlencode
from oauthlib.oauth2 import TokenExpiredError, OAuth2Error
from oauthlib.oauth2 import MismatchingStateError
from oauthlib.oauth2 import WebApplicationClient, MobileApplicationClient
from oauthlib.oauth2 import LegacyApplicationClient, BackendApplicationClient
from requests_oauthlib import OAuth2Session, TokenUpdated
from requests_oauthlib import AudienceBindingPolicy, AudienceViolationError
import requests
from requests.adapters import HTTPAdapter
from requests.models import Response

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


class RecordingHTTPAdapter(HTTPAdapter):
    """In-memory adapter that records every request actually transmitted.

    Routes map a URL prefix to a ``(status_code, location)`` tuple; when a
    ``location`` is returned the regular requests redirect machinery drives
    the next hop back through this adapter, which records it as well.
    """

    def __init__(self, routes=None, default_status=200, json_body=None):
        super(RecordingHTTPAdapter, self).__init__()
        self.routes = routes or {}
        self.default_status = default_status
        self.json_body = json_body
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append(request)

        response = Response()
        response.status_code = self.default_status
        location = None
        for prefix, spec in self.routes.items():
            if request.url.startswith(prefix):
                response.status_code = spec[0]
                if len(spec) > 1:
                    location = spec[1]
                break
        if location is not None:
            response.headers["Location"] = location
        if self.json_body is not None:
            response._content = json.dumps(self.json_body).encode()
        response.url = request.url
        response.request = request
        response.raw = mock.MagicMock()
        response.raw._original_response = None
        return response


def _audience_session(audience, routes=None, token=None, **kwargs):
    token = token or {
        "token_type": "Bearer",
        "access_token": "secret-access-token",
        "expires_in": 3600,
    }
    session = OAuth2Session(token=token, audience=audience, **kwargs)
    adapter = RecordingHTTPAdapter(routes)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session, adapter


class AudienceBindingPolicyTest(TestCase):
    def test_matches_scheme_host_port_and_path_scope(self):
        policy = AudienceBindingPolicy(["https://svc.internal:8443/api/v1"])
        self.assertTrue(policy.allows("https://svc.internal:8443/api/v1"))
        self.assertTrue(
            policy.allows("https://svc.internal:8443/api/v1/items?x=1#frag")
        )
        # query string and fragment never widen the audience
        self.assertTrue(policy.allows("https://svc.internal:8443/api/v1?x=1"))
        # same host, different port is a different audience
        self.assertFalse(policy.allows("https://svc.internal:9443/api/v1/items"))
        self.assertFalse(policy.allows("http://svc.internal:8443/api/v1/items"))
        # path prefix is segment based, no string-prefix shortcut
        self.assertFalse(policy.allows("https://svc.internal:8443/api/v1other"))
        self.assertFalse(policy.allows("https://svc.internal:8443/api/v2/x"))
        self.assertFalse(policy.allows("https://other.host:8443/api/v1/x"))

    def test_default_ports_are_normalized(self):
        policy = AudienceBindingPolicy(["https://svc.internal/v1"])
        self.assertTrue(policy.allows("https://svc.internal:443/v1/x"))
        self.assertFalse(policy.allows("https://svc.internal:8443/v1/x"))

    def test_accepts_several_audiences(self):
        policy = AudienceBindingPolicy(
            ["https://a.internal/v1", "https://b.internal/v2"]
        )
        self.assertTrue(policy.allows("https://a.internal/v1/items"))
        self.assertTrue(policy.allows("https://b.internal/v2/items"))
        self.assertFalse(policy.allows("https://a.internal/v2/items"))

    def test_rejects_bad_arguments(self):
        self.assertRaises(ValueError, AudienceBindingPolicy, [])
        self.assertRaises(
            ValueError, AudienceBindingPolicy, ["not-an-absolute-url"]
        )
        self.assertRaises(
            ValueError,
            AudienceBindingPolicy,
            ["https://a.internal/"],
            on_violation="explode",
        )

    def test_callable_policy(self):
        policy = AudienceBindingPolicy.from_callable(
            lambda url: url.startswith("https://svc.internal/v1/")
        )
        self.assertTrue(policy.allows("https://svc.internal/v1/items"))
        self.assertFalse(policy.allows("https://svc.internal/v2/items"))

    def test_build_audience_policy_coercion(self):
        from requests_oauthlib.audience import build_audience_policy

        self.assertIsNone(build_audience_policy(None))
        policy = AudienceBindingPolicy(["https://a.internal/"])
        self.assertIs(build_audience_policy(policy), policy)
        self.assertIsInstance(
            build_audience_policy("https://a.internal/"), AudienceBindingPolicy
        )
        self.assertIsInstance(
            build_audience_policy(lambda url: True), AudienceBindingPolicy
        )


class OAuth2SessionAudienceTest(TestCase):
    AUDIENCE = ["https://svc.internal:8443/api"]
    BEARER = "Bearer secret-access-token"

    def _recorded(self, adapter, url):
        matches = [r for r in adapter.sent if r.url.startswith(url)]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_allowed_audience_receives_bearer_token(self):
        session, adapter = _audience_session(self.AUDIENCE)
        session.get("https://svc.internal:8443/api/items")
        request = self._recorded(adapter, "https://svc.internal:8443/api/items")
        self.assertEqual(request.headers.get("Authorization"), self.BEARER)

    def test_same_host_different_port_is_denied(self):
        session, adapter = _audience_session(self.AUDIENCE)
        session.get("https://svc.internal:9443/api/items")
        request = self._recorded(adapter, "https://svc.internal:9443")
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("Proxy-Authorization", request.headers)

    def test_path_scope_is_enforced(self):
        session, adapter = _audience_session(["https://svc.internal/api/v1"])
        session.get("https://svc.internal/api/v1/items")
        session.get("https://svc.internal/api/v1other")
        session.get("https://svc.internal/api/v2/items")

        allowed = self._recorded(
            adapter, "https://svc.internal/api/v1/items"
        )
        self.assertEqual(allowed.headers.get("Authorization"), self.BEARER)
        for url in (
            "https://svc.internal/api/v1other",
            "https://svc.internal/api/v2/items",
        ):
            denied = self._recorded(adapter, url)
            self.assertNotIn("Authorization", denied.headers)

    def test_denied_request_is_still_sent_without_credentials(self):
        session, adapter = _audience_session(self.AUDIENCE)
        response = session.get("https://svc.internal:9443/api/items")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(adapter.sent), 1)
        self.assertNotIn("Authorization", adapter.sent[0].headers)

    def test_explicit_withhold_token_within_audience(self):
        session, adapter = _audience_session(self.AUDIENCE)
        session.get("https://svc.internal:8443/api/items", withhold_token=True)
        request = self._recorded(adapter, "https://svc.internal:8443/api/items")
        self.assertNotIn("Authorization", request.headers)

    def test_tokenless_request_to_denied_target_still_executes(self):
        session = OAuth2Session(audience=self.AUDIENCE)
        adapter = RecordingHTTPAdapter()
        session.mount("https://", adapter)
        response = session.get("https://svc.internal:9443/api/items")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(adapter.sent), 1)
        self.assertNotIn("Authorization", adapter.sent[0].headers)

    def test_redirect_to_denied_port_loses_token(self):
        routes = {
            "https://svc.internal:8443/api/start": (
                302,
                "https://svc.internal:9443/api/final",
            )
        }
        session, adapter = _audience_session(self.AUDIENCE, routes=routes)
        response = session.get("https://svc.internal:8443/api/start")

        self.assertEqual(len(adapter.sent), 2)
        self.assertEqual(
            adapter.sent[0].headers.get("Authorization"), self.BEARER
        )
        self.assertNotIn("Authorization", adapter.sent[1].headers)
        self.assertEqual(
            response.url, "https://svc.internal:9443/api/final"
        )

    def test_redirect_leaving_path_scope_loses_token(self):
        # Same host and port: requests itself would keep the Authorization
        # header, so the audience policy is the only line of defense.
        routes = {
            "https://svc.internal:8443/api/start": (
                302,
                "https://svc.internal:8443/other/final",
            )
        }
        session, adapter = _audience_session(self.AUDIENCE, routes=routes)
        response = session.get("https://svc.internal:8443/api/start")

        self.assertEqual(len(adapter.sent), 2)
        self.assertEqual(
            adapter.sent[0].headers.get("Authorization"), self.BEARER
        )
        self.assertNotIn("Authorization", adapter.sent[1].headers)
        self.assertEqual(response.url, "https://svc.internal:8443/other/final")

    def test_redirect_within_audience_keeps_token(self):
        routes = {
            "https://svc.internal:8443/api/start": (
                302,
                "https://svc.internal:8443/api/final",
            )
        }
        session, adapter = _audience_session(self.AUDIENCE, routes=routes)
        session.get("https://svc.internal:8443/api/start")
        self.assertEqual(len(adapter.sent), 2)
        for request in adapter.sent:
            self.assertEqual(
                request.headers.get("Authorization"), self.BEARER
            )

    def test_compliance_hook_redirected_to_denied_target(self):
        session, adapter = _audience_session(self.AUDIENCE)

        def rewrite_to_denied(url, headers, data):
            return "https://evil.internal/collect", headers, data

        session.register_compliance_hook("protected_request", rewrite_to_denied)
        session.get("https://svc.internal:8443/api/items")

        self.assertEqual(len(adapter.sent), 1)
        self.assertEqual(adapter.sent[0].url, "https://evil.internal/collect")
        self.assertNotIn("Authorization", adapter.sent[0].headers)

    def test_basic_auth_credentials_are_withheld(self):
        session, adapter = _audience_session(self.AUDIENCE)
        session.get(
            "https://svc.internal:9443/api/items",
            auth=("someclientid", "someclientsecret"),
        )
        request = self._recorded(adapter, "https://svc.internal:9443")
        self.assertNotIn("Authorization", request.headers)

    def test_proxy_authorization_header_is_withheld(self):
        session, adapter = _audience_session(self.AUDIENCE)
        session.get(
            "https://svc.internal:9443/api/items",
            headers={"Proxy-Authorization": "Bearer proxy-token"},
        )
        request = self._recorded(adapter, "https://svc.internal:9443")
        self.assertNotIn("Proxy-Authorization", request.headers)

    def test_fetch_token_to_denied_endpoint_strips_client_credentials(self):
        token = {
            "token_type": "Bearer",
            "access_token": "new-token",
            "expires_in": 3600,
        }
        session = OAuth2Session(
            client=BackendApplicationClient("someclientid"),
            audience=self.AUDIENCE,
        )
        adapter = RecordingHTTPAdapter(json_body=token)
        session.mount("https://", adapter)

        session.fetch_token(
            "https://token.evil.test/token",
            include_client_id=True,
            client_secret="someclientsecret",
        )

        self.assertEqual(len(adapter.sent), 1)
        request = adapter.sent[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("client_id", request.body)
        self.assertNotIn("client_secret", request.body)
        self.assertIn("grant_type=client_credentials", request.body)

    def test_raise_mode_blocks_denied_request(self):
        session, adapter = _audience_session(
            self.AUDIENCE, on_audience_violation="raise"
        )
        self.assertRaises(
            AudienceViolationError,
            session.get,
            "https://svc.internal:9443/api/items",
        )
        self.assertEqual(adapter.sent, [])

    def test_raise_mode_blocks_denied_redirect_hop(self):
        routes = {
            "https://svc.internal:8443/api/start": (
                302,
                "https://evil.internal/final",
            )
        }
        session, adapter = _audience_session(
            self.AUDIENCE, routes=routes, on_audience_violation="raise"
        )
        self.assertRaises(
            AudienceViolationError,
            session.get,
            "https://svc.internal:8443/api/start",
        )
        # The first, approved hop was sent; the denied redirect never was.
        self.assertEqual(len(adapter.sent), 1)
        self.assertEqual(
            adapter.sent[0].headers.get("Authorization"), self.BEARER
        )

    def test_refresh_token_to_denied_endpoint_strips_client_credentials(self):
        token = {
            "token_type": "Bearer",
            "access_token": "secret-access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
        }
        session = OAuth2Session(token=token, audience=self.AUDIENCE)
        adapter = RecordingHTTPAdapter(json_body=token)
        session.mount("https://", adapter)

        session.refresh_token(
            "https://auth.evil.test/refresh",
            auth=("someclientid", "someclientsecret"),
        )

        self.assertEqual(len(adapter.sent), 1)
        request = adapter.sent[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertIn("grant_type=refresh_token", request.body)

    def test_callable_audience_is_supported(self):
        session, adapter = _audience_session(
            lambda url: url.startswith("https://svc.internal:8443/api/")
        )
        session.get("https://svc.internal:8443/api/items")
        session.get("https://svc.internal:9443/api/items")
        self.assertEqual(
            adapter.sent[0].headers.get("Authorization"), self.BEARER
        )
        self.assertNotIn("Authorization", adapter.sent[1].headers)

    def test_existing_policy_object_is_supported(self):
        policy = AudienceBindingPolicy(self.AUDIENCE)
        session, adapter = _audience_session(policy)
        self.assertIs(session.audience_policy, policy)
        session.get("https://svc.internal:9443/api/items")
        self.assertNotIn("Authorization", adapter.sent[0].headers)

    def test_no_audience_keeps_legacy_behavior(self):
        session = OAuth2Session(
            token={
                "token_type": "Bearer",
                "access_token": "secret-access-token",
                "expires_in": 3600,
            }
        )
        adapter = RecordingHTTPAdapter()
        session.mount("https://", adapter)
        session.get("https://any-host.example/whatever")
        self.assertEqual(
            adapter.sent[0].headers.get("Authorization"), self.BEARER
        )
