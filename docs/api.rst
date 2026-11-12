.. _api:

Developer Interface
===================

.. module:: requests_oauthlib


OAuth 1.0
---------

.. autoclass:: OAuth1
    :members:


OAuth 1.0 Session
-----------------

.. autoclass:: OAuth1Session
    :members:


OAuth 2.0
---------

.. autoclass:: OAuth2
    :members:

.. autoclass:: TokenUpdated
    :members:


OAuth 2.0 Session
-----------------

.. autoclass:: OAuth2Session
    :members:


Token response normalization
----------------------------

.. automodule:: requests_oauthlib.token_normalization
    :members: TokenNormalizationAudit, TokenResponseError,
              inspect_vendor_token_response, normalize_vendor_token_response,
              vendor_token_compliance_fix
