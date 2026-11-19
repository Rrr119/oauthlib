"""
oauthlib.oauth2
~~~~~~~~~~~~~~

This module is a wrapper for the most recent implementation of OAuth 2.0 Client
and Server classes.
"""

from .rfc6749.clients import (
    BackendApplicationClient,
    Client,
    LegacyApplicationClient,
    MobileApplicationClient,
    ServiceApplicationClient,
    WebApplicationClient,
)
from .rfc6749.endpoints import (
    AuthorizationEndpoint,
    BackendApplicationServer,
    IntrospectEndpoint,
    LegacyApplicationServer,
    MetadataEndpoint,
    MobileApplicationServer,
    ResourceEndpoint,
    RevocationEndpoint,
    Server,
    TokenEndpoint,
    WebApplicationServer,
)
from .rfc6749.errors import (
    AccessDeniedError,
    FatalClientError,
    InsecureTransportError,
    InvalidClientError,
    InvalidClientIdError,
    InvalidGrantError,
    InvalidRedirectURIError,
    InvalidRequestError,
    InvalidRequestFatalError,
    InvalidScopeError,
    MismatchingRedirectURIError,
    MismatchingStateError,
    MissingClientIdError,
    MissingCodeError,
    MissingRedirectURIError,
    MissingResponseTypeError,
    MissingTokenError,
    MissingTokenTypeError,
    OAuth2Error,
    ServerError,
    TemporarilyUnavailableError,
    TokenExpiredError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
    UnsupportedResponseModeError,
    UnsupportedResponseTypeError,
    UnsupportedTokenTypeError,
)
from .rfc6749.grant_types import (
    AuthorizationCodeGrant,
    ClientCredentialsGrant,
    ImplicitGrant,
    RefreshTokenGrant,
    ResourceOwnerPasswordCredentialsGrant,
)
from .rfc6749.jarm import (
    DEFAULT_JARM_EXPIRES_IN, FRAGMENT_JWT, FORM_POST_JWT, JARMError,
    JARM_RESPONSE_MODES, JARMValidationError, JWT, QUERY_JWT, create_jarm_claims,
    extract_jarm_response, is_jarm_response, parse_jarm_response,
    sign_jarm_response, validate_jarm_claims, validate_jarm_response,
)
from .rfc6749.request_validator import RequestValidator
from .rfc6749.tokens import BearerToken, OAuth2Token
from .rfc6749.utils import is_secure_transport
from .rfc8628.clients import DeviceClient
from .rfc8628.endpoints import DeviceApplicationServer, DeviceAuthorizationEndpoint
from .rfc8628.errors import AccessDenied, AuthorizationPendingError, ExpiredTokenError, SlowDownError
from .rfc8628.grant_types import DeviceCodeGrant
