import logging
import threading
from urllib.parse import urlsplit

from oauthlib.common import generate_token, urldecode
from oauthlib.oauth2 import WebApplicationClient, InsecureTransportError
from oauthlib.oauth2 import LegacyApplicationClient
from oauthlib.oauth2 import TokenExpiredError, is_secure_transport
import requests

log = logging.getLogger(__name__)


class TokenUpdated(Warning):
    def __init__(self, token):
        super(TokenUpdated, self).__init__()
        self.token = token


class ComplianceHookError(RuntimeError):
    """A compliance hook broke the hook execution contract.

    :ivar condition: Stable name of the violated contract condition, for
                     example ``"hook_return_value"``.
    :ivar hook: The hook that violated the contract, when attributable.
    :ivar cause: The original exception raised by the hook, if any. It is not
                 chained into the traceback so request data carried by a
                 provider exception cannot end up in diagnostics.
    """

    def __init__(self, condition, message, hook=None, cause=None):
        super(ComplianceHookError, self).__init__(message)
        self.condition = condition
        self.hook = hook
        self.cause = cause


class ComplianceHookSecurityError(ComplianceHookError):
    """A security postcondition failed after all compliance hooks ran."""


def _hook_label(hook):
    """Return a diagnostic label without rendering the hook or its closure."""
    return (
        getattr(hook, "__qualname__", None)
        or getattr(hook, "__name__", None)
        or type(hook).__name__
    )


_PRIMITIVE_CELL_TYPES = (type(None), bool, int, float, str, bytes)


def _cell_key(cell):
    try:
        value = cell.cell_contents
    except ValueError:
        return ("empty",)
    return _value_key(value)


def _value_key(value):
    if isinstance(value, _PRIMITIVE_CELL_TYPES):
        return ("value", type(value), value)
    if isinstance(value, tuple) and all(
        isinstance(item, _PRIMITIVE_CELL_TYPES) for item in value
    ):
        return ("tuple", value)
    return ("identity", id(value))


def _hook_key(hook):
    """Build an identity key used to make duplicate registration idempotent.

    Plain callables are identified by their code object. Hooks created by the
    same compliance-fix factory share that code object, so captured values
    (including ``session``) and defaults are included too: applying the same
    fix twice to the same session does not make the hook run twice, while
    separately configured hooks from one factory stay distinct.
    """
    code = getattr(hook, "__code__", None)
    if code is None:
        return ("callable", id(hook))
    closure_key = tuple(
        _cell_key(cell) for cell in (getattr(hook, "__closure__", None) or ())
    )
    defaults_key = tuple(
        _value_key(value) for value in (getattr(hook, "__defaults__", None) or ())
    )
    kwdefaults_key = tuple(
        (name, _value_key(value))
        for name, value in (getattr(hook, "__kwdefaults__", None) or {}).items()
    )
    self_obj = getattr(hook, "__self__", None)
    self_key = ("none",) if self_obj is None else ("identity", id(self_obj))
    return (
        getattr(hook, "__module__", None),
        getattr(hook, "__qualname__", None),
        code,
        self_key,
        closure_key,
        defaults_key,
        kwdefaults_key,
    )


class _OrderedHookSet:
    """Insertion-ordered, duplicate-safe collection of compliance hooks."""

    def __init__(self):
        self._hooks = []
        self._keys = set()

    def add(self, hook):
        key = _hook_key(hook)
        if key in self._keys:
            log.debug("Ignoring duplicate compliance hook %s.", _hook_label(hook))
            return False
        self._keys.add(key)
        self._hooks.append(hook)
        return True

    def __iter__(self):
        return iter(self._hooks)

    def __len__(self):
        return len(self._hooks)

    def __contains__(self, hook):
        return any(existing is hook for existing in self._hooks)

    def __repr__(self):
        return repr(self._hooks)


class OAuth2Session(requests.Session):
    """Versatile OAuth 2 extension to :class:`requests.Session`.

    Supports any grant type adhering to :class:`oauthlib.oauth2.Client` spec
    including the four core OAuth 2 grants.

    Can be used to create authorization urls, fetch tokens and access protected
    resources using the :class:`requests.Session` interface you are used to.

    - :class:`oauthlib.oauth2.WebApplicationClient` (default): Authorization Code Grant
    - :class:`oauthlib.oauth2.MobileApplicationClient`: Implicit Grant
    - :class:`oauthlib.oauth2.LegacyApplicationClient`: Password Credentials Grant
    - :class:`oauthlib.oauth2.BackendApplicationClient`: Client Credentials Grant

    Note that the only time you will be using Implicit Grant from python is if
    you are driving a user agent able to obtain URL fragments.
    """

    def __init__(
        self,
        client_id=None,
        client=None,
        auto_refresh_url=None,
        auto_refresh_kwargs=None,
        scope=None,
        redirect_uri=None,
        token=None,
        state=None,
        token_updater=None,
        pkce=None,
        **kwargs
    ):
        """Construct a new OAuth 2 client session.

        :param client_id: Client id obtained during registration
        :param client: :class:`oauthlib.oauth2.Client` to be used. Default is
                       WebApplicationClient which is useful for any
                       hosted application but not mobile or desktop.
        :param scope: List of scopes you wish to request access to
        :param redirect_uri: Redirect URI you registered as callback
        :param token: Token dictionary, must include access_token
                      and token_type.
        :param state: State string used to prevent CSRF. This will be given
                      when creating the authorization url and must be supplied
                      when parsing the authorization response.
                      Can be either a string or a no argument callable.
        :auto_refresh_url: Refresh token endpoint URL, must be HTTPS. Supply
                           this if you wish the client to automatically refresh
                           your access tokens.
        :auto_refresh_kwargs: Extra arguments to pass to the refresh token
                              endpoint.
        :token_updater: Method with one argument, token, to be used to update
                        your token database on automatic token refresh. If not
                        set a TokenUpdated warning will be raised when a token
                        has been refreshed. This warning will carry the token
                        in its token argument.
        :param pkce: Set "S256" or "plain" to enable PKCE. Default is disabled.
        :param kwargs: Arguments to pass to the Session constructor.
        """
        super(OAuth2Session, self).__init__(**kwargs)
        self._client = client or WebApplicationClient(client_id, token=token)
        self.token = token or {}
        self._scope = scope
        self.redirect_uri = redirect_uri
        self.state = state or generate_token
        self._state = state
        self.auto_refresh_url = auto_refresh_url
        self.auto_refresh_kwargs = auto_refresh_kwargs or {}
        self.token_updater = token_updater
        self._pkce = pkce

        if self._pkce not in ["S256", "plain", None]:
            raise AttributeError("Wrong value for {}(.., pkce={})".format(self.__class__, self._pkce))

        # Ensure that requests doesn't do any automatic auth. See #278.
        # The default behavior can be re-enabled by setting auth to None.
        self.auth = lambda r: r

        # Allow customizations for non compliant providers through various
        # hooks to adjust requests and responses. Hooks run in registration
        # order and duplicate registrations are ignored; see
        # ``register_compliance_hook`` for the execution contract.
        self.compliance_hook = {
            "access_token_response": _OrderedHookSet(),
            "refresh_token_response": _OrderedHookSet(),
            "protected_request": _OrderedHookSet(),
            "refresh_token_request": _OrderedHookSet(),
            "access_token_request": _OrderedHookSet(),
        }

        # State carried from ``request`` into ``send`` so redirect hops can be
        # distinguished from the already-validated first transmission. It is
        # thread-local because a Session may be shared across threads.
        self._compliance_state = threading.local()

    @property
    def scope(self):
        """By default the scope from the client is used, except if overridden"""
        if self._scope is not None:
            return self._scope
        elif self._client is not None:
            return self._client.scope
        else:
            return None

    @scope.setter
    def scope(self, scope):
        self._scope = scope

    def new_state(self):
        """Generates a state string to be used in authorizations."""
        try:
            self._state = self.state()
            log.debug("Generated new state %s.", self._state)
        except TypeError:
            self._state = self.state
            log.debug("Re-using previously supplied state %s.", self._state)
        return self._state

    @property
    def client_id(self):
        return getattr(self._client, "client_id", None)

    @client_id.setter
    def client_id(self, value):
        self._client.client_id = value

    @client_id.deleter
    def client_id(self):
        del self._client.client_id

    @property
    def token(self):
        return getattr(self._client, "token", None)

    @token.setter
    def token(self, value):
        self._client.token = value
        self._client.populate_token_attributes(value)

    @property
    def access_token(self):
        return getattr(self._client, "access_token", None)

    @access_token.setter
    def access_token(self, value):
        self._client.access_token = value

    @access_token.deleter
    def access_token(self):
        del self._client.access_token

    @property
    def authorized(self):
        """Boolean that indicates whether this session has an OAuth token
        or not. If `self.authorized` is True, you can reasonably expect
        OAuth-protected requests to the resource to succeed. If
        `self.authorized` is False, you need the user to go through the OAuth
        authentication dance before OAuth-protected requests to the resource
        will succeed.
        """
        return bool(self.access_token)

    def authorization_url(self, url, state=None, **kwargs):
        """Form an authorization URL.

        :param url: Authorization endpoint url, must be HTTPS.
        :param state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
        :param kwargs: Extra parameters to include.
        :return: authorization_url, state
        """
        state = state or self.new_state()
        if self._pkce:
            self._code_verifier = self._client.create_code_verifier(43)
            kwargs["code_challenge_method"] = self._pkce
            kwargs["code_challenge"] = self._client.create_code_challenge(
                code_verifier=self._code_verifier,
                code_challenge_method=self._pkce
            )
        return (
            self._client.prepare_request_uri(
                url,
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                state=state,
                **kwargs
            ),
            state,
        )

    def fetch_token(
        self,
        token_url,
        code=None,
        authorization_response=None,
        body="",
        auth=None,
        username=None,
        password=None,
        method="POST",
        force_querystring=False,
        timeout=None,
        headers=None,
        verify=None,
        proxies=None,
        include_client_id=None,
        client_secret=None,
        cert=None,
        **kwargs
    ):
        """Generic method for fetching an access token from the token endpoint.

        If you are using the MobileApplicationClient you will want to use
        `token_from_fragment` instead of `fetch_token`.

        The current implementation enforces the RFC guidelines.

        :param token_url: Token endpoint URL, must use HTTPS.
        :param code: Authorization code (used by WebApplicationClients).
        :param authorization_response: Authorization response URL, the callback
                                       URL of the request back to you. Used by
                                       WebApplicationClients instead of code.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by `requests`.
        :param username: Username required by LegacyApplicationClients to appear
                         in the request body.
        :param password: Password required by LegacyApplicationClients to appear
                         in the request body.
        :param method: The HTTP method used to make the request. Defaults
                       to POST, but may also be GET. Other methods should
                       be added as needed.
        :param force_querystring: If True, force the request body to be sent
            in the querystring instead.
        :param timeout: Timeout of the request in seconds.
        :param headers: Dict to default request headers with.
        :param verify: Verify SSL certificate.
        :param proxies: The `proxies` argument is passed onto `requests`.
        :param include_client_id: Should the request body include the
                                  `client_id` parameter. Default is `None`,
                                  which will attempt to autodetect. This can be
                                  forced to always include (True) or never
                                  include (False).
        :param client_secret: The `client_secret` paired to the `client_id`.
                              This is generally required unless provided in the
                              `auth` tuple. If the value is `None`, it will be
                              omitted from the request, however if the value is
                              an empty string, an empty string will be sent.
        :param cert: Client certificate to send for OAuth 2.0 Mutual-TLS Client
                     Authentication (draft-ietf-oauth-mtls). Can either be the
                     path of a file containing the private key and certificate or
                     a tuple of two filenames for certificate and key.
        :param kwargs: Extra parameters to include in the token request.
        :return: A token dict
        """
        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        if not code and authorization_response:
            self._client.parse_request_uri_response(
                authorization_response, state=self._state
            )
            code = self._client.code
        elif not code and isinstance(self._client, WebApplicationClient):
            code = self._client.code
            if not code:
                raise ValueError(
                    "Please supply either code or " "authorization_response parameters."
                )

        if self._pkce:
            if self._code_verifier is None:
                raise ValueError(
                    "Code verifier is not found, authorization URL must be generated before"
                )
            kwargs["code_verifier"] = self._code_verifier

        # Earlier versions of this library build an HTTPBasicAuth header out of
        # `username` and `password`. The RFC states, however these attributes
        # must be in the request body and not the header.
        # If an upstream server is not spec compliant and requires them to
        # appear as an Authorization header, supply an explicit `auth` header
        # to this function.
        # This check will allow for empty strings, but not `None`.
        #
        # References
        # 4.3.2 - Resource Owner Password Credentials Grant
        #         https://tools.ietf.org/html/rfc6749#section-4.3.2

        if isinstance(self._client, LegacyApplicationClient):
            if username is None:
                raise ValueError(
                    "`LegacyApplicationClient` requires both the "
                    "`username` and `password` parameters."
                )
            if password is None:
                raise ValueError(
                    "The required parameter `username` was supplied, "
                    "but `password` was not."
                )

        # merge username and password into kwargs for `prepare_request_body`
        if username is not None:
            kwargs["username"] = username
        if password is not None:
            kwargs["password"] = password

        # is an auth explicitly supplied?
        if auth is not None:
            # if we're dealing with the default of `include_client_id` (None):
            # we will assume the `auth` argument is for an RFC compliant server
            # and we should not send the `client_id` in the body.
            # This approach allows us to still force the client_id by submitting
            # `include_client_id=True` along with an `auth` object.
            if include_client_id is None:
                include_client_id = False

        # otherwise we may need to create an auth header
        else:
            # since we don't have an auth header, we MAY need to create one
            # it is possible that we want to send the `client_id` in the body
            # if so, `include_client_id` should be set to True
            # otherwise, we will generate an auth header
            if include_client_id is not True:
                client_id = self.client_id
                if client_id:
                    log.debug(
                        'Encoding `client_id` "%s" with `client_secret` '
                        "as Basic auth credentials.",
                        client_id,
                    )
                    client_secret = client_secret if client_secret is not None else ""
                    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)

        if include_client_id:
            # this was pulled out of the params
            # it needs to be passed into prepare_request_body
            if client_secret is not None:
                kwargs["client_secret"] = client_secret

        body = self._client.prepare_request_body(
            code=code,
            body=body,
            redirect_uri=self.redirect_uri,
            include_client_id=include_client_id,
            **kwargs
        )

        headers = headers or {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.token = {}
        request_kwargs = {}
        if method.upper() == "POST":
            request_kwargs["params" if force_querystring else "data"] = dict(
                urldecode(body)
            )
        elif method.upper() == "GET":
            request_kwargs["params"] = dict(urldecode(body))
        else:
            raise ValueError("The method kwarg must be POST or GET.")

        sensitive_values = []
        if client_secret:
            sensitive_values.append(client_secret)
        password = getattr(auth, "password", None)
        if isinstance(password, str) and password:
            sensitive_values.append(password)

        baseline = self._target_features(
            token_url, params=request_kwargs.get("params")
        )
        baseline["sensitive_query"] = self._query_has_any(
            baseline.get("query"), sensitive_values
        )

        token_url, headers, request_kwargs = self._run_compliance_hooks(
            "access_token_request", token_url, headers, request_kwargs
        )

        self._assert_request_security(
            token_url,
            sensitive_values=sensitive_values,
            params=request_kwargs.get("params"),
            baseline=baseline,
        )

        r = self.request(
            method=method,
            url=token_url,
            timeout=timeout,
            headers=headers,
            auth=auth,
            verify=verify,
            proxies=proxies,
            cert=cert,
            _compliance_sensitive_values=sensitive_values,
            **request_kwargs
        )

        log.debug("Request to fetch token completed with status %s.", r.status_code)
        log.debug("Request url was %s", self._redact_url(r.request.url))
        log.debug("Response headers were %s.", r.headers)
        log.debug(
            "Invoking %d token response hooks.",
            len(self.compliance_hook["access_token_response"]),
        )
        r = self._run_compliance_response_hooks("access_token_response", r)

        self._client.parse_request_body_response(r.text, scope=self.scope)
        self.token = self._client.token
        log.debug("Obtained token from token endpoint.")
        return self.token

    def token_from_fragment(self, authorization_response):
        """Parse token from the URI fragment, used by MobileApplicationClients.

        :param authorization_response: The full URL of the redirect back to you
        :return: A token dict
        """
        self._client.parse_request_uri_response(
            authorization_response, state=self._state
        )
        self.token = self._client.token
        return self.token

    def refresh_token(
        self,
        token_url,
        refresh_token=None,
        body="",
        auth=None,
        timeout=None,
        headers=None,
        verify=None,
        proxies=None,
        **kwargs
    ):
        """Fetch a new access token using a refresh token.

        :param token_url: The token endpoint, must be HTTPS.
        :param refresh_token: The refresh_token to use.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by `requests`.
        :param timeout: Timeout of the request in seconds.
        :param headers: A dict of headers to be used by `requests`.
        :param verify: Verify SSL certificate.
        :param proxies: The `proxies` argument will be passed to `requests`.
        :param kwargs: Extra parameters to include in the token request.
        :return: A token dict
        """
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        refresh_token = refresh_token or self.token.get("refresh_token")

        log.debug("Adding auto refresh keyword arguments.")
        kwargs.update(self.auto_refresh_kwargs)
        body = self._client.prepare_refresh_body(
            body=body, refresh_token=refresh_token, scope=self.scope, **kwargs
        )
        log.debug("Prepared refresh token request body.")

        if headers is None:
            headers = {
                "Accept": "application/json",
                "Content-Type": ("application/x-www-form-urlencoded"),
            }

        token_url, headers, body = self._run_compliance_hooks(
            "refresh_token_request", token_url, headers, body
        )

        sensitive_values = ()
        password = getattr(auth, "password", None)
        if isinstance(password, str) and password:
            sensitive_values = (password,)

        self._assert_request_security(token_url, sensitive_values=sensitive_values)

        r = self.post(
            token_url,
            data=dict(urldecode(body)),
            auth=auth,
            timeout=timeout,
            headers=headers,
            verify=verify,
            withhold_token=True,
            proxies=proxies,
            _compliance_sensitive_values=sensitive_values,
        )
        log.debug("Request to refresh token completed with status %s.", r.status_code)
        log.debug("Response headers were %s.", r.headers)
        log.debug(
            "Invoking %d token response hooks.",
            len(self.compliance_hook["refresh_token_response"]),
        )
        r = self._run_compliance_response_hooks("refresh_token_response", r)

        self.token = self._client.parse_request_body_response(r.text, scope=self.scope)
        if "refresh_token" not in self.token:
            log.debug("No new refresh token given. Re-using old.")
            self.token["refresh_token"] = refresh_token
        return self.token

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        client_id=None,
        client_secret=None,
        files=None,
        **kwargs
    ):
        """Intercept all requests and add the OAuth 2 token if present."""
        sensitive_values = kwargs.pop("_compliance_sensitive_values", ())
        if client_secret:
            sensitive_values = tuple(sensitive_values) + (client_secret,)
        if not is_secure_transport(url):
            raise InsecureTransportError()
        baseline = self._target_features(url, params=kwargs.get("params"))
        baseline["sensitive_query"] = self._query_has_any(
            baseline.get("query"), sensitive_values
        )
        if self.token and not withhold_token:
            log.debug(
                "Invoking %d protected resource request hooks.",
                len(self.compliance_hook["protected_request"]),
            )
            url, headers, data = self._run_compliance_hooks(
                "protected_request", url, headers, data
            )

            self._assert_request_security(
                url,
                sensitive_values=sensitive_values,
                params=kwargs.get("params"),
                baseline=baseline,
            )

            log.debug("Adding an access token to the request.")
            try:
                url, headers, data = self._client.add_token(
                    url, http_method=method, body=data, headers=headers
                )
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                if self.auto_refresh_url:
                    log.debug(
                        "Auto refresh is set, attempting to refresh at %s.",
                        self.auto_refresh_url,
                    )

                    # We mustn't pass auth twice.
                    auth = kwargs.pop("auth", None)
                    if client_id and client_secret and (auth is None):
                        log.debug(
                            "Encoding client_id with client_secret as Basic "
                            "auth credentials."
                        )
                        auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
                    token = self.refresh_token(
                        self.auto_refresh_url, auth=auth, **kwargs
                    )
                    if self.token_updater:
                        log.debug("Updating token using the token updater.")
                        self.token_updater(token)
                        url, headers, data = self._client.add_token(
                            url, http_method=method, body=data, headers=headers
                        )
                    else:
                        raise TokenUpdated(token)
                else:
                    raise

        self._assert_request_security(
            url,
            sensitive_values=sensitive_values,
            params=kwargs.get("params"),
            baseline=baseline,
        )

        log.debug(
            "Requesting url %s using method %s.", self._redact_url(url), method
        )
        log.debug("Supplying %d request headers.", len(headers or {}))
        log.debug("Passing through key word arguments %s.", kwargs)
        # The final target was already validated above; remember its
        # baseline so ``send`` can distinguish the first transmission from a
        # redirect hop (``requests`` may normalize the URL before sending).
        state = self._compliance_state
        state.sensitive_values = tuple(sensitive_values)
        state.first_hop_baseline = baseline
        state.first_hop_pending = True
        state.request_active = True
        try:
            return super(OAuth2Session, self).request(
                method, url, headers=headers, data=data, files=files, **kwargs
            )
        finally:
            state.sensitive_values = ()
            state.first_hop_baseline = None
            state.first_hop_pending = False
            state.request_active = False

    def send(self, request, **kwargs):
        """Validate every prepared request, including redirect hops.

        ``requests`` follows redirects by calling ``send`` again with a copied
        prepared request. Checking here guarantees that a redirect target is
        validated before it is transmitted, not after the response arrives.
        """
        url = getattr(request, "url", None)
        if isinstance(url, str):
            state = self._compliance_state
            sensitive_values = getattr(state, "sensitive_values", ())
            if getattr(state, "first_hop_pending", False):
                baseline = getattr(state, "first_hop_baseline", None)
                state.first_hop_pending = False
                self._assert_request_security(
                    url, sensitive_values=sensitive_values, baseline=baseline
                )
            elif not getattr(state, "request_active", False):
                # A caller invoked ``send`` directly, bypassing ``request``.
                # No compliance hook rewrote this target, so keep the
                # historical transport error type while still rejecting it.
                if not is_secure_transport(url):
                    raise InsecureTransportError()
            else:
                # A redirect hop produced by ``requests``; no pre-hook
                # baseline exists for it, so all postconditions apply.
                self._assert_request_security(
                    url, sensitive_values=sensitive_values
                )
        return super(OAuth2Session, self).send(request, **kwargs)

    def _run_compliance_hooks(self, hook_type, *args):
        """Run request-side hooks in registration order.

        Hooks are invoked sequentially and must return a tuple with the same
        arity as their input. The first failure stops execution; later hooks
        are never invoked against partially transformed arguments.
        """
        for hook in self.compliance_hook[hook_type]:
            label = _hook_label(hook)
            log.debug("Invoking %s hook %s.", hook_type, label)
            try:
                result = hook(*args)
            except ComplianceHookError:
                raise
            except Exception as exc:
                raise ComplianceHookError(
                    "hook_execution",
                    "Compliance hook {} raised {}; execution stopped.".format(
                        label, type(exc).__name__
                    ),
                    hook=hook,
                    cause=exc,
                ) from None
            if not isinstance(result, tuple) or len(result) != len(args):
                raise ComplianceHookError(
                    "hook_return_value",
                    "Compliance hook {} must return a {}-tuple, got {}.".format(
                        label, len(args), type(result).__name__
                    ),
                    hook=hook,
                )
            args = result
        return args

    def _run_compliance_response_hooks(self, hook_type, response):
        """Run response-side hooks in registration order."""
        for hook in self.compliance_hook[hook_type]:
            label = _hook_label(hook)
            log.debug("Invoking %s hook %s.", hook_type, label)
            try:
                result = hook(response)
            except ComplianceHookError:
                raise
            except Exception as exc:
                raise ComplianceHookError(
                    "hook_execution",
                    "Compliance hook {} raised {}; execution stopped.".format(
                        label, type(exc).__name__
                    ),
                    hook=hook,
                    cause=exc,
                ) from None
            if result is None or not hasattr(result, "text"):
                raise ComplianceHookError(
                    "hook_return_value",
                    "Compliance hook {} must return a response object, got {}.".format(
                        label, type(result).__name__
                    ),
                    hook=hook,
                )
            response = result
        return response

    @staticmethod
    def _redact_url(url):
        """Render a URL without userinfo, query or fragment."""
        if not isinstance(url, str):
            return "<non-string-url>"
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
        except ValueError:
            return "<unparseable-url>"
        return "{}://{}{}".format(parts.scheme or "?", host, parts.path)

    @staticmethod
    def _target_features(url, params=None):
        """Describe the security-relevant features of a request target."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return {"parseable": False}
        query_parts = [parts.query] if parts.query else []
        if isinstance(params, dict):
            query_parts.extend(
                "{}={}".format(key, value) for key, value in params.items()
            )
        elif isinstance(params, (list, tuple)):
            query_parts.extend("{}={}".format(key, value) for key, value in params)
        return {
            "parseable": True,
            "url": url,
            "userinfo": parts.username is not None or parts.password is not None,
            "fragment": bool(parts.fragment),
            "query": "&".join(query_parts),
        }

    @staticmethod
    def _query_has_any(query, sensitive_values):
        """Return True if any sensitive value appears in an encoded query."""
        if not query:
            return False
        from urllib.parse import unquote

        haystack = unquote(query)
        return any(
            isinstance(secret, str) and secret and secret in haystack
            for secret in sensitive_values
        )

    def _assert_request_security(
        self, url, sensitive_values=(), params=None, baseline=None
    ):
        """Enforce security postconditions on the final request target.

        This runs after every request-side compliance hook, immediately
        before the request is handed to ``requests``. It exists because a
        target that passed an earlier check may be rewritten by a later hook.
        ``baseline`` is the result of :meth:`_target_features` computed before
        hooks ran: pre-existing choices such as an explicit ``force_querystring``
        are allowed, but hooks may not introduce a new violation.

        Error messages name the violated condition and only include a
        redacted target; request bodies, headers and query values are never
        used as diagnostics.
        """
        features = self._target_features(url, params)
        redacted = self._redact_url(url)
        baseline = baseline or {}

        if not features["parseable"]:
            raise ComplianceHookSecurityError(
                "url_parse",
                "Condition 'url_parse' violated: compliance hooks produced "
                "an unparseable request target.",
            )

        if not is_secure_transport(url):
            raise ComplianceHookSecurityError(
                "secure_transport",
                "Condition 'secure_transport' violated: the final request "
                "target {} is not HTTPS.".format(redacted),
            )

        if features["userinfo"] and not baseline.get("userinfo", False):
            raise ComplianceHookSecurityError(
                "url_userinfo",
                "Condition 'url_userinfo' violated: the final request target "
                "{} contains embedded credentials.".format(redacted),
            )

        if features["fragment"] and not baseline.get("fragment", False):
            raise ComplianceHookSecurityError(
                "url_fragment",
                "Condition 'url_fragment' violated: the final request target "
                "{} contains a fragment, which is not transmitted.".format(redacted),
            )

        if sensitive_values:
            query_was_sensitive = baseline.get("sensitive_query", False)
            if not query_was_sensitive and self._query_has_any(
                features["query"], sensitive_values
            ):
                raise ComplianceHookSecurityError(
                    "client_secret_in_url",
                    "Condition 'client_secret_in_url' violated: the final "
                    "request target {} carries a client secret in the query "
                    "string.".format(redacted),
                )

    def register_compliance_hook(self, hook_type, hook):
        """Register a hook for request/response tweaking.

        Available hooks are:
            access_token_response invoked before token parsing.
            refresh_token_response invoked before refresh token parsing.
            protected_request invoked before making a request.
            access_token_request invoked before making a token fetch request.
            refresh_token_request invoked before making a refresh request.

        Execution contract:

        - Hooks run sequentially in registration order, never in set order.
        - Registering the same hook (or re-applying a compliance fix to the
          same session) is idempotent: the hook runs once.
        - Request-side hooks receive ``(url, headers, data)`` and must return
          the same three values. Response-side hooks receive a response and
          must return a response. The first hook that raises an exception or
          returns an invalid value stops execution with
          :class:`ComplianceHookError`; subsequent hooks do not run.
        - Security postconditions (HTTPS transport, no embedded credentials,
          no fragment, no client secret in the query string) are re-checked
          after all hooks, immediately before the request is sent, and again
          for every redirect hop before that hop is transmitted. Violations
          raise :class:`ComplianceHookSecurityError`, whose ``condition``
          names the failed check. Diagnostics contain only a redacted URL;
          request bodies, headers and query values are never echoed.

        If you find a new hook is needed please send a GitHub PR request
        or open an issue.
        """
        if hook_type not in self.compliance_hook:
            raise ValueError(
                "Hook type %s is not in %s.", hook_type, self.compliance_hook
            )
        self.compliance_hook[hook_type].add(hook)
