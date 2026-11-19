# -*- coding: utf-8 -*-
import time
import urllib.parse as urlparse
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from oauthlib.oauth2 import (
    JARMValidationError, MobileApplicationClient, Server, WebApplicationClient,
    extract_jarm_response, sign_jarm_response, validate_jarm_response,
)
from oauthlib.oauth2.rfc6749 import errors

from tests.unittest import TestCase


ISSUER = "https://authorization.example"
CLIENT_ID = "client-123"
SECRET = "jarm-test-secret-with-at-least-32-bytes"


class JARMHelpersTest(TestCase):

    def test_sign_and_validate_with_pyjwt_interop(self):
        token = sign_jarm_response(
            {"code": "code-123", "state": "state-123"},
            SECRET,
            algorithm="HS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
        )

        # A general purpose JOSE client can verify the same token.
        claims = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            issuer=ISSUER,
            audience=CLIENT_ID,
        )
        self.assertEqual(claims["code"], "code-123")
        self.assertEqual(claims["state"], "state-123")
        self.assertEqual(claims["iss"], ISSUER)
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertIn("exp", claims)

        validated = validate_jarm_response(
            token,
            ISSUER,
            CLIENT_ID,
            SECRET,
            algorithms=["HS256"],
        )
        self.assertEqual(validated, claims)

    def test_rejects_wrong_issuer(self):
        token = sign_jarm_response(
            {"code": "code-123"},
            SECRET,
            algorithm="HS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
        )
        with self.assertRaisesRegex(JARMValidationError, "iss"):
            validate_jarm_response(
                token,
                "https://attacker.example",
                CLIENT_ID,
                SECRET,
                algorithms=["HS256"],
            )

    def test_rejects_wrong_audience(self):
        token = sign_jarm_response(
            {"code": "code-123"},
            SECRET,
            algorithm="HS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
        )
        with self.assertRaisesRegex(JARMValidationError, "aud"):
            validate_jarm_response(
                token,
                ISSUER,
                "another-client",
                SECRET,
                algorithms=["HS256"],
            )

    def test_rejects_expired_response(self):
        token = sign_jarm_response(
            {"code": "code-123"},
            SECRET,
            algorithm="HS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
            issued_at=int(time.time()) - 600,
            expires_in=10,
        )
        with self.assertRaisesRegex(JARMValidationError, "expired"):
            validate_jarm_response(
                token,
                ISSUER,
                CLIENT_ID,
                SECRET,
                algorithms=["HS256"],
            )

    def test_rejects_invalid_signature(self):
        token = sign_jarm_response(
            {"code": "code-123"},
            SECRET,
            algorithm="HS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
        )
        with self.assertRaises(JARMValidationError):
            validate_jarm_response(
                token,
                ISSUER,
                CLIENT_ID,
                "a-different-secret-with-at-least-32-bytes",
                algorithms=["HS256"],
            )

    def test_rs256_round_trip(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        token = sign_jarm_response(
            {"code": "code-123"},
            private_key,
            algorithm="RS256",
            issuer=ISSUER,
            audience=CLIENT_ID,
        )
        claims = validate_jarm_response(
            token,
            ISSUER,
            CLIENT_ID,
            private_key.public_key(),
        )
        self.assertEqual(claims["code"], "code-123")

    def test_extracts_response_from_all_jarm_transports(self):
        token = "header.payload.signature"
        quoted = urlparse.quote(token)
        self.assertEqual(
            extract_jarm_response("https://client.example/cb?response=" + quoted),
            token,
        )
        self.assertEqual(
            extract_jarm_response("https://client.example/cb#response=" + quoted),
            token,
        )
        self.assertEqual(
            extract_jarm_response("response=" + quoted),
            token,
        )

    def test_rejects_duplicate_response_parameters(self):
        with self.assertRaisesRegex(ValueError, "Multiple response"):
            extract_jarm_response(
                "https://client.example/cb?response=a.b.c&response=d.e.f")


class JARMServerClientInteropTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock()
        self.validator.validate_client_id.return_value = True
        self.validator.validate_redirect_uri.return_value = True
        self.validator.validate_response_type.return_value = True
        self.validator.validate_scopes.return_value = True
        self.validator.is_pkce_required.return_value = False
        self.validator.get_jarm_response.return_value = None
        self.validator.finalize_jarm_response.return_value = None
        self.validator.get_jarm_issuer.return_value = ISSUER
        self.validator.get_jarm_signing_key.return_value = SECRET
        self.validator.get_jarm_signing_alg.return_value = "HS256"
        self.server = Server(self.validator)

    def authorization_uri(self, response_type, response_mode, extra=""):
        return (
            "https://authorization.example/authorize"
            "?response_type={}&client_id={}"
            "&redirect_uri=https%3A%2F%2Fclient.example%2Fcb"
            "&state=state-123&scope=read&response_mode={}{}"
        ).format(response_type, CLIENT_ID, response_mode, extra)

    def web_client(self):
        return WebApplicationClient(
            CLIENT_ID,
            issuer=ISSUER,
            jarm_key=SECRET,
            jarm_algorithms=["HS256"],
        )

    def mobile_client(self):
        return MobileApplicationClient(
            CLIENT_ID,
            issuer=ISSUER,
            jarm_key=SECRET,
            jarm_algorithms=["HS256"],
        )

    @mock.patch("oauthlib.common.generate_token", new=lambda: "code-123")
    def test_authorization_code_query_jwt_round_trip(self):
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("code", "query.jwt"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)

        location = headers["Location"]
        self.assertIn("?response=", location)
        self.assertNotIn("code=", location)
        self.assertNotIn("state=", location)

        client = self.web_client()
        response = client.parse_request_uri_response(
            location, state="state-123")
        self.assertEqual(response["code"], "code-123")
        self.assertEqual(response["iss"], ISSUER)
        self.assertEqual(response["aud"], CLIENT_ID)
        self.assertEqual(client.code, "code-123")

        _url, _headers, body = client.prepare_token_request(
            "https://authorization.example/token",
            authorization_response=location,
            state="state-123",
            redirect_url="https://client.example/cb",
        )
        self.assertIn("code=code-123", body)

    @mock.patch("oauthlib.common.generate_token", new=lambda: "token-123")
    def test_implicit_fragment_jwt_round_trip(self):
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("token", "fragment.jwt"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)

        location = headers["Location"]
        self.assertIn("#response=", location)
        self.assertNotIn("access_token=", location)

        client = self.mobile_client()
        response = client.parse_request_uri_response(
            location, state="state-123")
        self.assertEqual(response["access_token"], "token-123")
        self.assertEqual(response["scope"], ["read"])
        self.assertEqual(client.access_token, "token-123")

    @mock.patch("oauthlib.common.generate_token", new=lambda: "code-123")
    def test_form_post_jwt_round_trip(self):
        headers, body, status = self.server.create_authorization_response(
            self.authorization_uri("code", "form_post.jwt"),
            scopes=["read"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html;charset=UTF-8")
        self.assertEqual(headers["Cache-Control"], "no-cache, no-store")

        client = self.web_client()
        response = client.parse_jarm_response(
            body,
            state="state-123",
        )
        self.assertEqual(response["code"], "code-123")
        self.assertEqual(response["iss"], ISSUER)
        self.assertEqual(response["aud"], CLIENT_ID)

    @mock.patch("oauthlib.common.generate_token", new=lambda: "code-123")
    def test_jwt_shortcut_uses_query_for_authorization_code(self):
        headers, _body, _status = self.server.create_authorization_response(
            self.authorization_uri("code", "jwt"),
            scopes=["read"],
        )
        self.assertIn("?response=", headers["Location"])

    @mock.patch("oauthlib.common.generate_token", new=lambda: "token-123")
    def test_jwt_shortcut_uses_fragment_for_implicit(self):
        headers, _body, _status = self.server.create_authorization_response(
            self.authorization_uri("token", "jwt"),
            scopes=["read"],
        )
        self.assertIn("#response=", headers["Location"])

    def test_error_response_is_a_jarm_jwt(self):
        self.validator.validate_scopes.return_value = False
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("code", "query.jwt"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)

        client = self.web_client()
        with self.assertRaises(errors.InvalidScopeError) as cm:
            client.parse_request_uri_response(
                headers["Location"], state="state-123")
        self.assertEqual(cm.exception.error, "invalid_scope")
        self.assertEqual(cm.exception.state, "state-123")

    @mock.patch("oauthlib.common.generate_token", new=lambda: "code-123")
    def test_validator_can_finalize_complete_response_without_issuer_hook(self):
        self.validator.get_jarm_issuer.return_value = None

        def finalize(response, _request):
            return sign_jarm_response(
                response,
                SECRET,
                algorithm="HS256",
                issuer=ISSUER,
                audience=CLIENT_ID,
            )

        self.validator.finalize_jarm_response.side_effect = finalize
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("code", "query.jwt"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)

        response = self.web_client().parse_request_uri_response(
            headers["Location"], state="state-123")
        self.assertEqual(response["code"], "code-123")
        self.assertEqual(response["iss"], ISSUER)

    def test_legacy_query_response_mode_is_unchanged(self):
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("code", "query"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)
        params = dict(urlparse.parse_qsl(
            urlparse.urlparse(headers["Location"]).query))
        self.assertIn("code", params)
        self.assertNotIn("response", params)

    def test_legacy_fragment_response_mode_is_unchanged(self):
        headers, _body, status = self.server.create_authorization_response(
            self.authorization_uri("token", "fragment"),
            scopes=["read"],
        )
        self.assertEqual(status, 302)
        params = dict(urlparse.parse_qsl(
            urlparse.urlparse(headers["Location"]).fragment))
        self.assertIn("access_token", params)
        self.assertNotIn("response", params)
