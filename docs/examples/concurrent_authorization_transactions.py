"""Demonstrate concurrent authorization transactions against a fake endpoint.

Run with: .venv/bin/python docs/examples/concurrent_authorization_transactions.py
No network access or real provider is required.
"""
import json

import requests_mock

from requests_oauthlib import (
    AuthorizationTransaction,
    AuthorizationTransactionRetryableError,
    OAuth2Session,
)

AUTHORIZE_URL = "https://provider.example/authorize"
TOKEN_URL = "https://provider.example/token"
REDIRECT_URI = "https://app.example/callback"


def token_handler(request, context):
    form = dict(pair.split("=", 1) for pair in (request.body or "").split("&"))
    if form.get("code") == "code-b":
        context.status_code = 503
        return "temporarily unavailable"
    context.status_code = 200
    return json.dumps(
        {
            "access_token": "token-for-" + form.get("code", "?"),
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )


def main():
    session = OAuth2Session("backend-client", redirect_uri=REDIRECT_URI, pkce="S256")

    # The application starts two flows and persists both transactions.
    recent = session.create_authorization_transaction(AUTHORIZE_URL)
    earlier = session.create_authorization_transaction(AUTHORIZE_URL)
    saved = {t.state: t.to_dict() for t in (recent, earlier)}
    print("started flow A:", earlier.state)
    print("started flow B:", recent.state)
    assert earlier.code_verifier != recent.code_verifier

    with requests_mock.Mocker() as mocker:
        mocker.post(TOKEN_URL, text=token_handler)

        # Callback B arrives first; it may only use B's material.
        restored_b = AuthorizationTransaction.from_dict(saved[recent.state])
        callback_b = REDIRECT_URI + "?code=code-b&state=" + restored_b.state
        try:
            session.fetch_token_for_transaction(
                restored_b, TOKEN_URL, authorization_response=callback_b
            )
        except AuthorizationTransactionRetryableError:
            print("flow B failed transiently; retryable:", restored_b.retryable)

        # Callback A arrives later, out of order.
        restored_a = AuthorizationTransaction.from_dict(saved[earlier.state])
        callback_a = REDIRECT_URI + "?code=code-a&state=" + restored_a.state
        token_a = session.fetch_token_for_transaction(
            restored_a, TOKEN_URL, authorization_response=callback_a
        )
        print("flow A token:", token_a["access_token"])

        # A duplicate callback for A must not exchange again.
        duplicate = REDIRECT_URI + "?code=code-a&state=" + restored_a.state
        try:
            session.fetch_token_for_transaction(
                restored_a, TOKEN_URL, authorization_response=duplicate
            )
        except Exception as exc:
            print("duplicate callback rejected:", type(exc).__name__)

        # Retrying B keeps the same verifier, then consumes it on success.
        retry_b = REDIRECT_URI + "?code=code-ok&state=" + restored_b.state
        token_b = session.fetch_token_for_transaction(
            restored_b, TOKEN_URL, authorization_response=retry_b
        )
        print("flow B token after retry:", token_b["access_token"])


if __name__ == "__main__":
    main()
