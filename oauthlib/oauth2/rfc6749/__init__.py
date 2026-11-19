"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import functools
import logging

from .endpoints.base import BaseEndpoint, catch_errors_and_unavailability
from .errors import (
    FatalClientError, OAuth2Error, ServerError, TemporarilyUnavailableError,
)
from .jarm import (
    DEFAULT_JARM_EXPIRES_IN, JARM_RESPONSE_MODES, JARMError, JARMValidationError,
    create_jarm_claims, extract_jarm_response, is_jarm_response,
    parse_jarm_response, sign_jarm_response, validate_jarm_claims,
    validate_jarm_response,
)

log = logging.getLogger(__name__)
