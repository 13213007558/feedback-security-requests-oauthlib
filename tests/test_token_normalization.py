import json
import time
from unittest import TestCase

import requests_mock

from oauthlib.oauth2 import BackendApplicationClient, OAuth2Error

from requests_oauthlib import OAuth2Session
from requests_oauthlib.token_normalization import (
    TokenResponseError,
    inspect_vendor_token_response,
    vendor_token_compliance_fix,
)


NOW = 1_700_000_000
TOKEN_URL = "https://vendor.example/oauth/token"
PROTECTED_URL = "https://vendor.example/resource"


def body(**fields):
    return json.dumps(fields)


def legacy(scope="read write", **overrides):
    token = {
        "access_token": "legacy-access",
        "refresh_token": "legacy-refresh",
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": scope,
    }
    token.update(overrides)
    return body(**token)


def modern(scope="read write", **overrides):
    token = {
        "accessToken": "modern-access",
        "refreshToken": "modern-refresh",
        "tokenType": "Bearer",
        "expiresIn": "3600",
        "expiresAt": NOW + 3600,
        "scope": scope,
    }
    token.update(overrides)
    return body(**token)


class NormalizationUnitTest(TestCase):
    def inspect(self, raw, scope=None, now=NOW, **kwargs):
        return inspect_vendor_token_response(
            raw, requested_scope=scope, now=now, **kwargs
        )

    def test_legacy_shape_is_normalized(self):
        audit = self.inspect(legacy(), ["read", "write"])
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.normalized_token["access_token"], "legacy-access")
        self.assertEqual(audit.normalized_token["expires_in"], 3600)
        self.assertEqual(audit.normalized_token["expires_at"], NOW + 3600)
        self.assertEqual(audit.normalized_token["scope"], "read write")
        self.assertIn("token_type: 'bearer' -> 'Bearer'", audit.conversions)

    def test_modern_shape_is_normalized(self):
        audit = self.inspect(modern(), ["read", "write"])
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.normalized_token["access_token"], "modern-access")
        self.assertEqual(audit.normalized_token["token_type"], "Bearer")
        self.assertEqual(audit.normalized_token["expires_in"], 3600)
        self.assertEqual(audit.normalized_token["expires_at"], NOW + 3600)
        self.assertIn("accessToken->access_token", audit.conversions)
        self.assertIn("expiresIn->expires_in", audit.conversions)

    def test_camel_case_relative_expiry_only(self):
        raw = body(accessToken="a", tokenType="bearer", expiresIn=1200)
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.normalized_token["expires_in"], 1200)
        self.assertEqual(audit.normalized_token["expires_at"], NOW + 1200)
        self.assertEqual(audit.normalized_token["token_type"], "Bearer")

    def test_mixed_fields_agree(self):
        raw = body(
            access_token="a",
            token_type="Bearer",
            expires_in=3600,
            expiresIn=3600,
            expires_at=NOW + 3600,
        )
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.normalized_token["expires_at"], NOW + 3600)
        self.assertIn(
            "expires_in aliases agree: expires_in, expiresIn",
            audit.duplicate_fields,
        )

    def test_mixed_fields_disagree_on_expiry(self):
        raw = body(
            access_token="a",
            token_type="Bearer",
            expires_in=3600,
            expiresAt=NOW + 7200,
        )
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("disagree", audit.reason)

    def test_duplicate_aliases_must_agree(self):
        raw = body(
            access_token="a",
            accessToken="b",
            token_type="Bearer",
            expires_in=3600,
        )
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("Conflicting values", audit.reason)

    def test_default_token_type_is_not_invented(self):
        raw = body(access_token="a", expires_in=3600)
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("Missing token_type", audit.reason)

    def test_unknown_token_type_is_rejected(self):
        raw = body(access_token="a", token_type="Admin", expires_in=3600)
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("Unsupported token_type", audit.reason)

    def test_invalid_expiry_values_are_rejected(self):
        for value in ("not-a-number", -1, 0, True, None):
            with self.subTest(value=value):
                raw = body(access_token="a", token_type="Bearer", expires_in=value)
                audit = self.inspect(raw)
                self.assertEqual(audit.status, "rejected")
                self.assertIsNone(audit.normalized_token)

    def test_past_absolute_expiry_is_rejected(self):
        raw = body(access_token="a", token_type="Bearer", expires_at=NOW - 1)
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("not in the future", audit.reason)

    def test_timezone_free_iso_expiry_is_rejected(self):
        raw = body(
            access_token="a",
            token_type="Bearer",
            expiresAt="2026-11-12T15:00:00",
        )
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("timezone", audit.reason)

    def test_iso_expiry_is_converted(self):
        raw = body(
            accessToken="a",
            tokenType="Bearer",
            expiresAt="2026-11-12T15:00:00Z",
        )
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertGreater(audit.normalized_token["expires_at"], NOW)
        self.assertIn("expires_at: ISO-8601 -> Unix seconds", audit.conversions)

    def test_expanded_scope_is_rejected(self):
        raw = legacy(scope="read write admin")
        audit = self.inspect(raw, ["read", "write"])
        self.assertEqual(audit.status, "rejected")
        self.assertIn("expands", audit.reason)
        self.assertIn("admin", audit.reason)

    def test_narrowed_scope_is_accepted_and_recorded(self):
        raw = legacy(scope="read")
        audit = self.inspect(raw, ["read", "write"])
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.granted_scope, ("read",))
        self.assertEqual(audit.requested_scope, ("read", "write"))

    def test_absent_scope_inherits_requested_range(self):
        raw = body(access_token="a", token_type="Bearer", expires_in=3600)
        audit = self.inspect(raw, ["read"])
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(audit.granted_scope, ("read",))

    def test_scope_without_requested_range_is_rejected(self):
        raw = legacy(scope="read")
        audit = self.inspect(raw)
        self.assertEqual(audit.status, "rejected")
        self.assertIn("no scope was requested", audit.reason)

    def test_unknown_fields_are_audited_not_promoted(self):
        raw = body(
            access_token="a",
            token_type="Bearer",
            expires_in=3600,
            roles=["admin"],
            is_admin=True,
        )
        audit = self.inspect(raw, ["read"])
        self.assertEqual(audit.status, "accepted", audit.reason)
        self.assertEqual(
            audit.unknown_fields, {"roles": ["admin"], "is_admin": True}
        )
        self.assertNotIn("roles", audit.normalized_token)
        self.assertNotIn("is_admin", audit.normalized_token)

    def test_error_response_is_flagged_not_normalized(self):
        audit = self.inspect(body(error="invalid_grant"))
        self.assertEqual(audit.status, "error_response")
        self.assertIsNone(audit.normalized_token)

    def test_error_with_token_material_is_rejected(self):
        audit = self.inspect(body(error="invalid_grant", access_token="a"))
        self.assertEqual(audit.status, "rejected")
        self.assertIn("both", audit.reason)

    def test_invalid_json_is_rejected_with_raw_preserved(self):
        audit = self.inspect("not json")
        self.assertEqual(audit.status, "rejected")
        self.assertEqual(audit.raw_body, "not json")
        self.assertIsNone(audit.raw_token)

    def test_audit_to_dict_is_reviewable(self):
        audit = self.inspect(legacy(), ["read", "write"])
        record = audit.to_dict()
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["raw_body"], legacy())
        self.assertEqual(record["requested_scope"], ["read", "write"])
        self.assertEqual(record["granted_scope"], ["read", "write"])
        self.assertEqual(
            record["normalized_token"]["access_token"], "legacy-access"
        )
        json.dumps(record)


class SessionIntegrationTest(TestCase):
    def setUp(self):
        self.mocker = requests_mock.Mocker()
        self.mocker.start()
        self.addCleanup(self.mocker.stop)
        self.session = OAuth2Session(
            client=BackendApplicationClient("someclientid"),
            scope=["read", "write"],
            redirect_uri="https://i.b",
        )
        self.session = vendor_token_compliance_fix(self.session, clock=NOW)

    def fetch(self, raw):
        self.mocker.post(TOKEN_URL, text=raw)
        return self.session.fetch_token(TOKEN_URL, include_client_id=True)

    def test_legacy_response_establishes_session(self):
        token = self.fetch(legacy())
        self.assertEqual(token["access_token"], "legacy-access")
        self.assertTrue(self.session.authorized)
        self.assertEqual(self.session.last_token_audit.status, "accepted")

    def test_modern_response_establishes_session(self):
        token = self.fetch(modern())
        self.assertEqual(token["access_token"], "modern-access")
        self.assertEqual(token["expires_at"], NOW + 3600)

    def test_failed_scope_expansion_keeps_previous_session(self):
        first = self.fetch(legacy())
        self.session.token = first
        self.mocker.post(TOKEN_URL, text=legacy(scope="read write admin"))
        with self.assertRaises(TokenResponseError) as caught:
            self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertIn("admin", str(caught.exception))
        self.assertEqual(self.session.token, first)
        self.assertEqual(self.session.access_token, "legacy-access")
        self.assertTrue(self.session.authorized)
        self.assertEqual(self.session.last_token_audit.status, "rejected")

    def test_failed_expiry_keeps_previous_session(self):
        first = self.fetch(legacy())
        self.mocker.post(
            TOKEN_URL,
            text=body(access_token="second", token_type="Bearer", expires_in=0),
        )
        with self.assertRaises(TokenResponseError):
            self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertEqual(self.session.token, first)
        self.assertEqual(self.session.access_token, "legacy-access")

    def test_oauthlib_error_keeps_previous_session(self):
        first = self.fetch(legacy())
        self.mocker.post(TOKEN_URL, text=body(error="invalid_grant"))
        with self.assertRaises(OAuth2Error):
            self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertEqual(self.session.token, first)
        self.assertEqual(self.session.last_token_audit.status, "error_response")

    def test_refresh_failure_keeps_previous_session(self):
        first = self.fetch(
            legacy(refresh_token="keep-me", access_token="first-access")
        )
        self.mocker.post(
            TOKEN_URL,
            text=body(access_token="x", token_type="Bearer", expires_in=-5),
        )
        with self.assertRaises(TokenResponseError):
            self.session.refresh_token(TOKEN_URL)
        self.assertEqual(self.session.token, first)
        self.assertEqual(self.session.token["refresh_token"], "keep-me")

    def test_refresh_success_replaces_token(self):
        self.fetch(legacy(refresh_token="keep-me"))
        self.mocker.post(TOKEN_URL, text=modern())
        token = self.session.refresh_token(TOKEN_URL)
        self.assertEqual(token["access_token"], "modern-access")
        self.assertEqual(token["refresh_token"], "modern-refresh")



    def test_refresh_cannot_recover_ungranted_requested_scope(self):
        first = self.fetch(legacy(scope="read"))
        self.mocker.post(TOKEN_URL, text=modern(scope="read write"))
        with self.assertRaises(TokenResponseError) as caught:
            self.session.refresh_token(TOKEN_URL)
        self.assertIn("previously granted scope", str(caught.exception))
        self.assertEqual(self.session.token, first)
        self.assertEqual(
            self.session.last_token_audit.previous_scope, ("read",)
        )

    def test_refresh_may_keep_granted_scope(self):
        self.fetch(legacy(scope="read write"))
        self.mocker.post(TOKEN_URL, text=modern(scope="read write"))
        token = self.session.refresh_token(TOKEN_URL)
        self.assertEqual(token["scope"], ["read", "write"])

    def test_narrowed_scope_does_not_raise_scope_warning(self):
        self.mocker.post(TOKEN_URL, text=legacy(scope="read"))
        token = self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertEqual(token["scope"], ["read"])
        self.assertEqual(
            self.session.last_token_audit.requested_scope, ("read", "write")
        )
        self.assertEqual(
            self.session.last_token_audit.granted_scope, ("read",)
        )

    def test_refresh_expanded_scope_keeps_previous_session(self):
        first = self.fetch(legacy())
        self.mocker.post(TOKEN_URL, text=modern(scope="read write admin"))
        with self.assertRaises(TokenResponseError):
            self.session.refresh_token(TOKEN_URL)
        self.assertEqual(self.session.token, first)
        self.assertEqual(
            self.session.last_token_audit.operation, "refresh_token"
        )

    def test_audit_retains_raw_body_and_unknown_fields(self):
        raw = body(
            accessToken="a",
            tokenType="Bearer",
            expiresIn=3600,
            scope="read",
            granted_roles=["admin"],
        )
        token = self.fetch(raw)
        audit = self.session.last_token_audit
        self.assertEqual(audit.operation, "access_token")
        self.assertEqual(audit.raw_body, raw)
        self.assertEqual(audit.unknown_fields, {"granted_roles": ["admin"]})
        self.assertEqual(token["access_token"], "a")
        self.assertNotIn("granted_roles", token)


    def test_non_json_response_preserves_session(self):
        first = self.fetch(legacy())
        self.mocker.post(TOKEN_URL, text="<html>gateway error</html>")
        with self.assertRaises(TokenResponseError):
            self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertEqual(self.session.token, first)
        self.assertEqual(
            self.session.last_token_audit.raw_body,
            "<html>gateway error</html>",
        )

    def test_malformed_json_keeps_error_body_but_state(self):
        first = self.fetch(legacy())
        self.mocker.post(TOKEN_URL, text='{"access_token": ')
        with self.assertRaises(TokenResponseError):
            self.session.fetch_token(TOKEN_URL, include_client_id=True)
        self.assertEqual(self.session.token, first)

    def test_protected_request_uses_normalized_token(self):
        self.fetch(legacy())
        self.session.token = dict(
            self.session.token,
            expires_in=3600,
            expires_at=time.time() + 3600,
        )
        self.mocker.get(PROTECTED_URL, json={"ok": True})
        response = self.session.get(PROTECTED_URL)
        self.assertEqual(
            response.request.headers["Authorization"], "Bearer legacy-access"
        )
