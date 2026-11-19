"""
oauthlib.oauth2.rfc6749.jarm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Helpers for JWT Secured Authorization Response Mode (JARM).

JARM serializes the authorization response parameters in a signed JWT and
returns that JWT as the ``response`` parameter.  The JWT always carries the
``iss``, ``aud`` and ``exp`` claims in addition to the response parameters.
"""
import html
import re
import time
import urllib.parse as urlparse
from collections.abc import Mapping


QUERY_JWT = "query.jwt"
FRAGMENT_JWT = "fragment.jwt"
FORM_POST_JWT = "form_post.jwt"
JWT = "jwt"

JARM_RESPONSE_MODES = frozenset((QUERY_JWT, FRAGMENT_JWT, FORM_POST_JWT, JWT))

DEFAULT_JARM_EXPIRES_IN = 120


class JARMError(ValueError):
    """Base exception for malformed or invalid JARM messages."""


class JARMValidationError(JARMError):
    """Raised when a JARM JWT cannot be verified or violates its claims."""


def _get_jwt_module():
    try:
        import jwt  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "JARM requires PyJWT. Install oauthlib with the "
            "'signedtoken' extra (pip install oauthlib[signedtoken])."
        ) from exc
    return jwt


def _require_string(value, name):
    if not isinstance(value, str) or not value:
        raise JARMError("{} must be a non-empty string.".format(name))
    return value


def _as_timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JARMValidationError("{} must be a NumericDate.".format(name))
    return value


def create_jarm_claims(response, issuer, audience, expires_in=DEFAULT_JARM_EXPIRES_IN,
                       issued_at=None, additional_claims=None):
    """Build the claims for a JARM authorization response.

    :param response: Authorization response parameters, e.g. ``code`` and
                     ``state``, or error parameters.
    :param issuer: Authorization server issuer identifier.
    :param audience: Client identifier that the response is intended for.
    :param expires_in: Lifetime of the response JWT in seconds.
    :param issued_at: Optional issuance time as a NumericDate.
    :param additional_claims: Optional claims added before the registered
                              claims are set.
    :returns: A claims dictionary ready to be signed.
    """
    _require_string(issuer, "issuer")
    _require_string(audience, "audience")
    if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
        raise JARMError("expires_in must be a number of seconds.")
    if expires_in <= 0:
        raise JARMError("expires_in must be greater than zero.")

    if response is None:
        response = {}
    if not isinstance(response, Mapping):
        raise JARMError("response must be a mapping.")

    now = int(time.time() if issued_at is None else issued_at)
    claims = dict(response)
    claims.update(additional_claims or {})

    # These claims describe the JWT itself and must not be controlled by the
    # authorization response parameters.
    claims["iss"] = issuer
    claims["aud"] = audience
    claims["iat"] = now
    claims["exp"] = now + int(expires_in)
    return claims


def sign_jarm_response(response, key, algorithm="RS256", issuer=None,
                       audience=None, expires_in=None,
                       issued_at=None, headers=None, additional_claims=None):
    """Create and sign a JARM authorization response JWT.

    ``issuer`` and ``audience`` may also be supplied in ``response``.  PyJWT is
    an optional dependency and is available through the ``signedtoken`` extra.

    :returns: The compact JWS serialization of the authorization response.
    """
    jwt = _get_jwt_module()
    if not isinstance(response, Mapping):
        raise JARMError("response must be a mapping.")
    issuer = issuer or response.get("iss")
    audience = audience or response.get("aud")
    _require_string(issuer, "issuer")
    _require_string(audience, "audience")
    claims = dict(response)
    claims.update(additional_claims or {})
    now = int(time.time() if issued_at is None else issued_at)
    claims["iss"] = issuer
    claims["aud"] = audience
    claims.setdefault("iat", now)
    if expires_in is not None:
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            raise JARMError("expires_in must be a number of seconds.")
        if expires_in <= 0:
            raise JARMError("expires_in must be greater than zero.")
        claims["exp"] = int(claims["iat"]) + int(expires_in)
    elif "exp" not in claims:
        claims["exp"] = now + DEFAULT_JARM_EXPIRES_IN
    token = jwt.encode(claims, key, algorithm=algorithm, headers=headers)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _extract_single_parameter(pairs, source):
    values = [value for name, value in pairs if name == "response"]
    if len(values) > 1:
        raise JARMError("Multiple response parameters in {}.".format(source))
    return values[0] if values else None


_HTML_RESPONSE_PATTERNS = (
    re.compile(
        r'name=["\']response["\'][^>]*value=["\']([^"\']+)["\']',
        re.IGNORECASE,
    ),
    re.compile(
        r'value=["\']([^"\']+)["\'][^>]*name=["\']response["\']',
        re.IGNORECASE,
    ),
)


def _extract_html_response(value):
    if "<" not in value or "response" not in value.lower():
        return None
    for pattern in _HTML_RESPONSE_PATTERNS:
        match = pattern.search(value)
        if match:
            return html.unescape(match.group(1))
    return None


def is_jarm_response(value):
    """Return whether ``value`` carries a JARM ``response`` parameter."""
    if isinstance(value, Mapping):
        return "response" in value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if not isinstance(value, str):
        return False
    value = value.strip()
    html_response = _extract_html_response(value)
    if html_response is not None:
        return True
    if value.count(".") == 2 and "=" not in value and "?" not in value and "#" not in value:
        return True
    parsed = urlparse.urlparse(value)
    for component in (parsed.query, parsed.fragment):
        if component and "response" in dict(urlparse.parse_qsl(component)):
            return True
    return not parsed.query and not parsed.fragment and "=" in value and (
        "response" in dict(urlparse.parse_qsl(value)))


def extract_jarm_response(value):
    """Extract a JARM JWT from a redirect URI, form body or mapping.

    Both query and fragment components are checked so this helper can be used
    with ``query.jwt``, ``fragment.jwt`` and ``form_post.jwt``.
    """
    if isinstance(value, Mapping):
        response = value.get("response")
        if response is None:
            raise JARMError("Missing response parameter.")
        return _require_string(response, "response")

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if not isinstance(value, str):
        raise JARMError("JARM response must be a string or mapping.")

    value = value.strip()
    html_response = _extract_html_response(value)
    if html_response is not None:
        return _require_string(html_response, "response")
    if value.count(".") == 2 and "=" not in value and "?" not in value and "#" not in value:
        return _require_string(value, "response")

    parsed = urlparse.urlparse(value)
    candidates = []
    if parsed.query:
        candidates.append((
            "query",
            _extract_single_parameter(urlparse.parse_qsl(parsed.query), "query"),
        ))
    if parsed.fragment:
        candidates.append((
            "fragment",
            _extract_single_parameter(
                urlparse.parse_qsl(parsed.fragment), "fragment"),
        ))

    # A form body is not a URL.  Parsing it as one still leaves the encoded
    # parameters in the path, so handle the plain form-encoded case as well.
    if not parsed.query and not parsed.fragment and "=" in value:
        candidates.append((
            "body",
            _extract_single_parameter(urlparse.parse_qsl(value), "body"),
        ))

    found = [(source, response) for source, response in candidates if response]
    if not found:
        raise JARMError("Missing response parameter.")
    if len(found) > 1 and found[0][1] != found[1][1]:
        raise JARMError("Conflicting response parameters in {} and {}.".format(
            found[0][0], found[1][0]))
    return _require_string(found[0][1], "response")


def _audience_matches(audience, expected):
    if isinstance(audience, str):
        return audience == expected
    if isinstance(audience, (list, tuple)):
        return expected in audience
    return False


_HMAC_ALGORITHMS = ("HS256", "HS384", "HS512")
_RSA_ALGORITHMS = (
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
)
_EC_ALGORITHMS = ("ES256", "ES384", "ES512")
_PEM_PREFIX = b"-----BEGIN"


def _algorithms_for_key(key):
    """Return a conservative algorithm allow-list for an inferred key type."""
    algorithms = ()
    if isinstance(key, Mapping):
        kty = key.get("kty")
        algorithms = {
            "RSA": _RSA_ALGORITHMS,
            "EC": _EC_ALGORITHMS,
            "oct": _HMAC_ALGORITHMS,
        }.get(kty, ())
    elif isinstance(key, (str, bytes)):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        algorithms = (
            _RSA_ALGORITHMS + _EC_ALGORITHMS + ("EdDSA",)
            if _PEM_PREFIX in key_bytes
            else _HMAC_ALGORITHMS
        )
    else:
        key_type = type(key)
        type_name = key_type.__name__
        if key_type.__module__.startswith("cryptography."):
            if "RSA" in type_name:
                algorithms = _RSA_ALGORITHMS
            elif "EllipticCurve" in type_name:
                algorithms = _EC_ALGORITHMS
            elif "Ed25519" in type_name or "Ed448" in type_name:
                algorithms = ("EdDSA",)

        if not algorithms:
            # PyJWT's PyJWK wrapper and custom key objects can expose the
            # underlying key.
            wrapped_key = getattr(key, "key", None)
            if wrapped_key is not None and wrapped_key is not key:
                algorithms = _algorithms_for_key(wrapped_key)

    return algorithms


def validate_jarm_claims(claims, issuer, audience, leeway=0, now=None):
    """Validate required JARM claims and return them.

    The issuer must match exactly, the audience must contain the requesting
    client identifier, and the JWT must not be expired.  ``leeway`` allows for
    a small clock skew in seconds.
    """
    _require_string(issuer, "issuer")
    _require_string(audience, "audience")
    if isinstance(leeway, bool) or not isinstance(leeway, (int, float)) or leeway < 0:
        raise JARMError("leeway must be a non-negative number of seconds.")
    if not isinstance(claims, Mapping):
        raise JARMValidationError("JARM claims must be a mapping.")

    for name in ("iss", "aud", "exp"):
        if name not in claims:
            raise JARMValidationError("Missing {} claim.".format(name))

    if claims["iss"] != issuer:
        raise JARMValidationError("Invalid iss claim.")
    if not _audience_matches(claims["aud"], audience):
        raise JARMValidationError("Invalid aud claim.")

    current_time = time.time() if now is None else now
    expiration = _as_timestamp(claims["exp"], "exp")
    if current_time >= expiration + leeway:
        raise JARMValidationError("JARM response has expired.")

    if "nbf" in claims:
        not_before = _as_timestamp(claims["nbf"], "nbf")
        if current_time + leeway < not_before:
            raise JARMValidationError("JARM response is not valid yet.")

    if "iat" in claims:
        issued_at = _as_timestamp(claims["iat"], "iat")
        if issued_at > current_time + leeway:
            raise JARMValidationError("Invalid iat claim.")

    return claims


def validate_jarm_response(token, issuer, audience, key=None, algorithms=None,
                           leeway=0, now=None, verify_signature=True):
    """Verify a JARM JWT and validate its ``iss``, ``aud`` and ``exp`` claims.

    :param token: Compact JWS serialization of the authorization response.
    :param issuer: Expected authorization server issuer identifier.
    :param audience: Expected client identifier.
    :param key: Key used to verify the JWS signature.
    :param algorithms: Allowed JWS algorithms.  When omitted, the algorithm is
                       read from the protected header.  Callers should pass an
                       explicit allow-list when handling untrusted messages.
    :param leeway: Allowed clock skew in seconds.
    :param now: Optional current time as a NumericDate, useful in tests.
    :param verify_signature: Set to ``False`` only when the signature was
                             already verified by the caller.
    :returns: The verified claims dictionary.
    """
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    token = _require_string(token, "token")
    if token.count(".") != 2:
        raise JARMValidationError(
            "JARM response must be a signed compact JWT.")

    claims = None
    if verify_signature:
        if key is None:
            raise JARMValidationError("A key is required to verify a JARM response.")
        jwt = _get_jwt_module()
        if algorithms is None:
            try:
                header_algorithm = jwt.get_unverified_header(token)["alg"]
            except (KeyError, jwt.PyJWTError) as exc:
                raise JARMValidationError("Invalid JARM JWT header.") from exc
            allowed_algorithms = _algorithms_for_key(key)
            if header_algorithm not in allowed_algorithms:
                raise JARMValidationError(
                    "JARM JWT algorithm is not allowed for this key.")
            algorithms = [header_algorithm]
        elif isinstance(algorithms, str):
            algorithms = [algorithms]

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(algorithms),
                options={
                    "require": ["iss", "aud", "exp"],
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iss": False,
                },
                leeway=leeway,
            )
        except jwt.PyJWTError as exc:
            raise JARMValidationError("Invalid JARM JWT.") from exc

    if claims is None:
        jwt = _get_jwt_module()
        try:
            claims = jwt.decode(
                token,
                options={"verify_signature": False},
            )
        except jwt.PyJWTError as exc:
            raise JARMValidationError("Invalid JARM JWT.") from exc

    return validate_jarm_claims(
        claims, issuer, audience, leeway=leeway, now=now)


def parse_jarm_response(value, issuer, audience, key=None, algorithms=None,
                        leeway=0, now=None, verify_signature=True):
    """Extract, verify and validate a JARM response.

    ``value`` may be a JWT, a redirect URI, a form-encoded body or a mapping
    containing the ``response`` parameter.
    """
    token = extract_jarm_response(value)
    return validate_jarm_response(
        token,
        issuer,
        audience,
        key,
        algorithms=algorithms,
        leeway=leeway,
        now=now,
        verify_signature=verify_signature,
    )


# Explicit aliases make the intended operation clear at call sites.
sign_jarm_jwt = sign_jarm_response
validate_jarm_jwt = validate_jarm_response
parse_jarm_jwt = parse_jarm_response
