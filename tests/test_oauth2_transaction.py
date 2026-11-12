import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest
import requests
import requests_mock
from oauthlib.oauth2 import MismatchingStateError

from requests_oauthlib import (
    OAuth2Session,
    AuthorizationTransaction,
    AuthorizationTransactionConsumedError,
    AuthorizationTransactionInProgressError,
    AuthorizationTransactionRedirectUriError,
    AuthorizationTransactionClientMismatchError,
    AuthorizationTransactionRetryableError,
)


AUTHORIZE_URL = "https://provider.example/authorize"
TOKEN_URL = "https://provider.example/token"


def callback_url(redirect_uri, code, state):
    separator = "&" if urlparse(redirect_uri).query else "?"
    return "%s%scode=%s&state=%s" % (redirect_uri, separator, code, state)


def token_response(code, verifier=None):
    def respond(request, context):
        form = parse_qs(request.body or "")
        assert form["code"] == [code]
        if verifier is not None:
            assert form["code_verifier"] == [verifier]
        context.status_code = 200
        return json.dumps(
            {
                "access_token": "access-for-" + code,
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

    return respond


def test_concurrent_transactions_are_independent():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback?a=1", pkce="S256"
    )
    first = session.create_authorization_transaction(AUTHORIZE_URL)
    second = session.create_authorization_transaction(
        AUTHORIZE_URL, redirect_uri="https://app.example/other-callback"
    )

    assert first.state != second.state
    assert first.code_verifier != second.code_verifier
    assert first.redirect_uri == "https://app.example/callback?a=1"
    assert second.redirect_uri == "https://app.example/other-callback"
    assert first.client_id == second.client_id == "backend-client"
    assert first.state in first.authorization_url
    assert second.state in second.authorization_url
    assert "code_challenge=" in first.authorization_url
    assert "code_challenge=" in second.authorization_url

    # Creating the second transaction must not overwrite the first one's
    # verification material, nor the legacy session state.
    assert first.pending and second.pending
    assert session._state is None
    assert not hasattr(session, "_code_verifier")


def test_callbacks_can_arrive_out_of_order():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    first = session.create_authorization_transaction(AUTHORIZE_URL)
    second = session.create_authorization_transaction(AUTHORIZE_URL)

    first_callback = callback_url(first.redirect_uri, "code-first", first.state)
    second_callback = callback_url(
        second.redirect_uri, "code-second", second.state
    )

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-second", second.code_verifier))
        second_token = session.fetch_token_for_transaction(
            second, TOKEN_URL, authorization_response=second_callback
        )
        assert second_token["access_token"] == "access-for-code-second"
        assert second.consumed

        mocker.post(TOKEN_URL, text=token_response("code-first", first.code_verifier))
        first_token = session.fetch_token_for_transaction(
            first, TOKEN_URL, authorization_response=first_callback
        )
        assert first_token["access_token"] == "access-for-code-first"
        assert first.consumed

    assert session.token == first_token


def test_duplicate_callback_is_rejected_without_a_second_exchange():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-once", transaction.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-once"))
        token = session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=callback
        )
        assert token["access_token"] == "access-for-code-once"
        assert transaction.consumed

        history_length = len(mocker.request_history)
        with pytest.raises(AuthorizationTransactionConsumedError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert len(mocker.request_history) == history_length


def test_callback_for_another_transaction_leaves_both_usable():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    first = session.create_authorization_transaction(AUTHORIZE_URL)
    second = session.create_authorization_transaction(AUTHORIZE_URL)

    first_callback = callback_url(first.redirect_uri, "code-first", first.state)
    second_callback = callback_url(second.redirect_uri, "code-second", second.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=token_response("code-first", first.code_verifier),
        )
        with pytest.raises(MismatchingStateError):
            session.fetch_token_for_transaction(
                second, TOKEN_URL, authorization_response=first_callback
            )
        assert mocker.call_count == 0
        assert first.pending and second.pending

        # Each transaction still consumes only its own verification material.
        first_token = session.fetch_token_for_transaction(
            first, TOKEN_URL, authorization_response=first_callback
        )
        assert first_token["access_token"] == "access-for-code-first"
        assert first.consumed and second.pending

    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=token_response("code-second", second.code_verifier),
        )
        second_token = session.fetch_token_for_transaction(
            second, TOKEN_URL, authorization_response=second_callback
        )
        assert second_token["access_token"] == "access-for-code-second"
        assert second.consumed


def test_redirect_uri_mismatch_does_not_consume_the_transaction():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    forged_callback = callback_url(
        "https://attacker.example/callback", "code-x", transaction.state
    )

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-x"))
        with pytest.raises(AuthorizationTransactionRedirectUriError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=forged_callback
            )
        assert mocker.call_count == 0
        assert transaction.pending


def test_client_mismatch_does_not_consume_the_transaction():
    creator = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = creator.create_authorization_transaction(AUTHORIZE_URL)
    other = OAuth2Session(
        "other-client", redirect_uri="https://app.example/callback"
    )

    with pytest.raises(AuthorizationTransactionClientMismatchError):
        other.fetch_token_for_transaction(
            transaction,
            TOKEN_URL,
            code="code-x",
        )
    assert transaction.pending


def test_invalid_grant_consumes_transaction_and_cannot_be_retried():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "bad-code", transaction.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            status_code=400,
            text=json.dumps({"error": "invalid_grant"}),
        )
        with pytest.raises(Exception) as excinfo:
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert "invalid_grant" in str(excinfo.value)
        assert transaction.failed
        assert not transaction.retryable
        assert transaction.failure["type"] == "InvalidGrantError"

        history_length = len(mocker.request_history)
        with pytest.raises(AuthorizationTransactionConsumedError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert len(mocker.request_history) == history_length


def test_transient_server_error_is_retryable_with_same_material():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-retry", transaction.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, status_code=503, text="try again later")
        with pytest.raises(AuthorizationTransactionRetryableError) as excinfo:
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert excinfo.value.__cause__ is not None
        assert transaction.failed and transaction.retryable
        assert transaction.failure["status_code"] == 503
        assert len(mocker.request_history) == 1

        mocker.post(
            TOKEN_URL,
            text=token_response("code-retry", transaction.code_verifier),
        )
        token = session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=callback
        )
        assert token["access_token"] == "access-for-code-retry"
        assert transaction.consumed


def test_network_failure_is_retryable_with_same_material():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-net", transaction.state)

    def unavailable(request, **kwargs):
        raise requests.exceptions.ConnectionError("connection reset")

    session.send = unavailable
    with pytest.raises(AuthorizationTransactionRetryableError):
        session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=callback
        )
    assert transaction.retryable
    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=token_response("code-net", transaction.code_verifier),
        )
        del session.send
        token = session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=callback
        )
        assert token["access_token"] == "access-for-code-net"
        assert transaction.consumed


def test_transaction_round_trip_through_json():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    payload = json.loads(json.dumps(transaction.to_dict()))
    restored = AuthorizationTransaction.from_dict(payload)

    assert restored.state == transaction.state
    assert restored.code_verifier == transaction.code_verifier
    assert restored.redirect_uri == transaction.redirect_uri
    assert restored.client_id == transaction.client_id
    assert restored.pkce == "S256"
    assert restored.pending
    assert "access_token" not in payload
    assert "client_secret" not in payload

    callback = callback_url(restored.redirect_uri, "code-restored", restored.state)
    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=token_response("code-restored", restored.code_verifier),
        )
        token = session.fetch_token_for_transaction(
            restored, TOKEN_URL, authorization_response=callback
        )
    assert token["access_token"] == "access-for-code-restored"
    assert restored.consumed
    assert transaction.pending  # only the restored copy was consumed


def test_legacy_single_flow_still_works():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    authorization_url, state = session.authorization_url(AUTHORIZE_URL)
    assert state in authorization_url

    callback = callback_url(session.redirect_uri, "legacy-code", state)
    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=token_response("legacy-code", session._code_verifier),
        )
        token = session.fetch_token(
            TOKEN_URL, authorization_response=callback
        )
    assert token["access_token"] == "access-for-legacy-code"



def test_malformed_callback_state_leaves_transaction_pending():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)

    for bad_callback in (
        "https://app.example/callback?code=c",
        "https://app.example/callback?code=c&state=",
        "https://app.example/callback?code=c&state=%s&state=%s"
        % (transaction.state, transaction.state),
    ):
        with pytest.raises(MismatchingStateError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=bad_callback
            )
        assert transaction.pending

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-ok"))
        good_callback = callback_url(
            transaction.redirect_uri, "code-ok", transaction.state
        )
        token = session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=good_callback
        )
    assert token["access_token"] == "access-for-code-ok"


def test_transaction_bound_parameters_cannot_be_overridden():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)

    with pytest.raises(ValueError):
        session.fetch_token_for_transaction(
            transaction,
            TOKEN_URL,
            authorization_response=callback_url(
                transaction.redirect_uri, "code-x", transaction.state
            ),
            code_verifier="substituted",
        )
    assert transaction.pending


def test_concurrent_use_of_one_transaction_is_rejected(monkeypatch):
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-x", transaction.state)

    original = session._fetch_token_with_transaction

    def nested(*args, **kwargs):
        with pytest.raises(AuthorizationTransactionInProgressError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(session, "_fetch_token_with_transaction", nested)
    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-x"))
        token = session.fetch_token_for_transaction(
            transaction, TOKEN_URL, authorization_response=callback
        )
    assert token["access_token"] == "access-for-code-x"


def test_success_response_parse_failure_consumes_transaction():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-bad", transaction.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, status_code=200, text="{}")
        with pytest.raises(Exception):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert transaction.failed
        assert not transaction.retryable

        history_length = len(mocker.request_history)
        with pytest.raises(AuthorizationTransactionConsumedError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
        assert len(mocker.request_history) == history_length



def test_user_denied_callback_consumes_transaction():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    denied = (
        transaction.redirect_uri
        + "?error=access_denied&state="
        + transaction.state
    )

    with requests_mock.Mocker() as mocker:
        with pytest.raises(Exception) as excinfo:
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=denied
            )
    assert "access_denied" in str(excinfo.value)
    assert mocker.call_count == 0
    assert transaction.consumed
    assert not transaction.retryable
    assert transaction.failure["type"] == "AccessDeniedError"


def test_retry_keeps_all_binding_material():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    before = transaction.to_dict()

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, status_code=502, text="bad gateway")
        with pytest.raises(AuthorizationTransactionRetryableError):
            session.fetch_token_for_transaction(
                transaction,
                TOKEN_URL,
                authorization_response=callback_url(
                    transaction.redirect_uri, "code-r", transaction.state
                ),
            )
    after = transaction.to_dict()
    for key in (
        "state",
        "client_id",
        "redirect_uri",
        "code_verifier",
        "pkce",
        "code_challenge",
        "scope",
        "authorization_url",
    ):
        assert after[key] == before[key]
    assert after["status"] == "failed"
    assert after["retryable"] is True



def test_two_transactions_can_exchange_concurrently():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback", pkce="S256"
    )
    first = session.create_authorization_transaction(AUTHORIZE_URL)
    second = session.create_authorization_transaction(AUTHORIZE_URL)
    results = {}

    def exchange(name, transaction):
        callback = callback_url(
            transaction.redirect_uri, "code-" + name, transaction.state
        )
        results[name] = session.fetch_token_for_transaction(
            transaction,
            TOKEN_URL,
            authorization_response=callback,
            update_session_token=False,
        )

    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            text=lambda request, context: _thread_token(request, context),
        )
        threads = [
            threading.Thread(target=exchange, args=("a", first)),
            threading.Thread(target=exchange, args=("b", second)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert results["a"]["access_token"] == "access-for-code-a"
    assert results["b"]["access_token"] == "access-for-code-b"
    assert first.consumed and second.consumed


def _thread_token(request, context):
    form = parse_qs(request.body or "")
    context.status_code = 200
    return json.dumps(
        {
            "access_token": "access-for-" + form["code"][0],
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )


def test_existing_legacy_token_does_not_leak_into_transaction():
    session = OAuth2Session(
        "backend-client",
        redirect_uri="https://app.example/callback",
        token={"access_token": "old", "token_type": "Bearer"},
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-new"))
        token = session.fetch_token_for_transaction(
            transaction,
            TOKEN_URL,
            authorization_response=callback_url(
                transaction.redirect_uri, "code-new", transaction.state
            ),
        )
    assert token["access_token"] == "access-for-code-new"
    assert session.token["access_token"] == "access-for-code-new"


def test_update_session_token_false_leaves_shared_state_alone():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_response("code-x"))
        token = session.fetch_token_for_transaction(
            transaction,
            TOKEN_URL,
            authorization_response=callback_url(
                transaction.redirect_uri, "code-x", transaction.state
            ),
            update_session_token=False,
        )
    assert token["access_token"] == "access-for-code-x"
    assert not session.authorized



def test_temporarily_unavailable_oauth_error_is_retryable():
    session = OAuth2Session(
        "backend-client", redirect_uri="https://app.example/callback"
    )
    transaction = session.create_authorization_transaction(AUTHORIZE_URL)
    callback = callback_url(transaction.redirect_uri, "code-t", transaction.state)

    with requests_mock.Mocker() as mocker:
        mocker.post(
            TOKEN_URL,
            status_code=400,
            text=json.dumps({"error": "temporarily_unavailable"}),
        )
        with pytest.raises(AuthorizationTransactionRetryableError):
            session.fetch_token_for_transaction(
                transaction, TOKEN_URL, authorization_response=callback
            )
    assert transaction.retryable
    assert transaction.failure["error"] == "temporarily_unavailable"
