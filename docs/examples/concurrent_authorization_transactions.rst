Concurrent Authorization Transactions
=====================================

A backend service may have several authorization round-trips in flight for the
same user. ``OAuth2Session.authorization_url`` stores a single state and PKCE
verifier on the session, so starting a second flow overwrites the first one's
verification material.

:class:`~requests_oauthlib.AuthorizationTransaction` binds each round-trip to
its own state, PKCE verifier, client identifier and redirect URI. The
application persists the transaction between the redirect and the callback,
for example in a server-side session or a database, keyed by its state.

.. code-block:: python

    from requests_oauthlib import OAuth2Session

    session = OAuth2Session("backend-client", redirect_uri=redirect_uri, pkce="S256")
    transaction = session.create_authorization_transaction(authorization_url)

    # Persist this server-side; it contains the PKCE verifier, so treat the
    # stored value as a secret and never send it to the browser or logs.
    store[transaction.state] = transaction.to_dict()
    return redirect(transaction.authorization_url)

On the callback, route by the callback's single ``state`` value, restore the
transaction, and exchange the code with only that transaction's material:

.. code-block:: python

    from requests_oauthlib import AuthorizationTransaction

    state = AuthorizationTransaction.state_from_response(request.url)
    transaction = AuthorizationTransaction.from_dict(store.pop(state))
    token = session.fetch_token_for_transaction(
        transaction, token_url, authorization_response=request.url
    )

Callbacks may arrive out of order: processing one transaction never validates,
consumes or rewrites another transaction. A successful exchange consumes the
transaction, so a duplicate callback raises
:class:`~requests_oauthlib.AuthorizationTransactionConsumedError` without
sending a second token request.

Failure handling is explicit:

* A callback whose ``state`` belongs to another transaction, a redirect URI
  mismatch or a client mismatch leaves the transaction pending and usable.
* HTTP 408, 425, 429, HTTP 5xx, network failures and the OAuth
  ``temporarily_unavailable``/``server_error`` errors leave the transaction
  retryable; :class:`~requests_oauthlib.AuthorizationTransactionRetryableError`
  is raised and a retry reuses the same state, verifier, client and redirect
  URI.
* ``invalid_grant``, other terminal token-endpoint errors and malformed
  responses consume the transaction, blocking replay of the authorization code.

The single-flow ``authorization_url``/``fetch_token`` API is unchanged. A
runnable demonstration against a fake token endpoint is in
``docs/examples/concurrent_authorization_transactions.py``.
