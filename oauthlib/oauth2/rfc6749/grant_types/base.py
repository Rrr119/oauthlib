"""
oauthlib.oauth2.rfc6749.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import functools
import html
import logging
from itertools import chain

from oauthlib.common import add_params_to_uri
from oauthlib.oauth2.rfc6749 import errors, jarm, utils
from oauthlib.uri_validate import is_absolute_uri

from ..request_validator import RequestValidator
from ..utils import is_secure_transport

log = logging.getLogger(__name__)


def revalidate_response_mode(validate):
    """Validate the response mode again once request validation is done.

    Custom validators may set the response mode, e.g. from a request object,
    so it is validated again after they ran, whether or not they raised.
    An unsupported response mode then takes precedence over normal errors,
    which also get the response mode used to return them.
    """
    @functools.wraps(validate)
    def wrapper(self, request, *args, **kwargs):
        try:
            result = validate(self, request, *args, **kwargs)
        except errors.FatalClientError:
            raise
        except errors.OAuth2Error as e:
            error = e
        else:
            self._validate_response_mode(request)
            return result
        # Validated outside of the except clause, so that an unsupported
        # response mode is not chained to the normal error it replaces.
        try:
            self._validate_response_mode(request)
            error.response_mode = request.response_mode
            raise error
        finally:
            # Break the reference cycle between the error and this frame.
            del error
    return wrapper


class ValidatorsContainer:
    """
    Container object for holding custom validator callables to be invoked
    as part of the grant type `validate_authorization_request()` or
    `validate_authorization_request()` methods on the various grant types.

    Authorization validators must be callables that take a request object and
    return a dict, which may contain items to be added to the `request_info`
    returned from the grant_type after validation.

    Token validators must be callables that take a request object and
    return None.

    Both authorization validators and token validators may raise OAuth2
    exceptions if validation conditions fail.

    Authorization validators added to `pre_auth` will be run BEFORE
    the standard validations (but after the critical ones that raise
    fatal errors) as part of `validate_authorization_request()`

    Authorization validators added to `post_auth` will be run AFTER
    the standard validations as part of `validate_authorization_request()`

    Token validators added to `pre_token` will be run BEFORE
    the standard validations as part of `validate_token_request()`

    Token validators added to `post_token` will be run AFTER
    the standard validations as part of `validate_token_request()`

    For example:

    >>> def my_auth_validator(request):
    ...    return {'myval': True}
    >>> auth_code_grant = AuthorizationCodeGrant(request_validator)
    >>> auth_code_grant.custom_validators.pre_auth.append(my_auth_validator)
    >>> def my_token_validator(request):
    ...     if not request.everything_okay:
    ...         raise errors.OAuth2Error("uh-oh")
    >>> auth_code_grant.custom_validators.post_token.append(my_token_validator)
    """

    def __init__(self, post_auth, post_token,
                 pre_auth, pre_token):
        self.pre_auth = pre_auth
        self.post_auth = post_auth
        self.pre_token = pre_token
        self.post_token = post_token

    @property
    def all_pre(self):
        return chain(self.pre_auth, self.pre_token)

    @property
    def all_post(self):
        return chain(self.post_auth, self.post_token)


class GrantTypeBase:
    error_uri = None
    request_validator = None
    default_response_mode = 'fragment'
    _response_modes = (
        'query',
        'fragment',
        jarm.QUERY_JWT,
        jarm.FRAGMENT_JWT,
        jarm.FORM_POST_JWT,
        jarm.JWT,
    )
    jarm_response_expires_in = jarm.DEFAULT_JARM_EXPIRES_IN
    refresh_token = True
    response_types = ['code']

    def __init__(self, request_validator=None, **kwargs):
        self.request_validator = request_validator or RequestValidator()

        # Transforms class variables into instance variables:
        self.response_types = self.response_types
        self.refresh_token = self.refresh_token
        self._setup_custom_validators(kwargs)
        self._code_modifiers = []
        self._token_modifiers = []

        for kw, val in kwargs.items():
            setattr(self, kw, val)

    def _setup_custom_validators(self, kwargs):
        post_auth = kwargs.get('post_auth', [])
        post_token = kwargs.get('post_token', [])
        pre_auth = kwargs.get('pre_auth', [])
        pre_token = kwargs.get('pre_token', [])
        if not hasattr(self, 'validate_authorization_request'):
            if post_auth or pre_auth:
                msg = ("{} does not support authorization validators. Use "
                       "token validators instead.").format(self.__class__.__name__)
                raise ValueError(msg)
            # Using tuples here because they can't be appended to:
            post_auth, pre_auth = (), ()
        self.custom_validators = ValidatorsContainer(post_auth, post_token,
                                                     pre_auth, pre_token)

    def register_response_type(self, response_type):
        self.response_types.append(response_type)

    def register_code_modifier(self, modifier):
        self._code_modifiers.append(modifier)

    def register_token_modifier(self, modifier):
        self._token_modifiers.append(modifier)

    def create_authorization_response(self, request, token_handler):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def create_token_response(self, request, token_handler):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def add_token(self, token, token_handler, request):
        """
        :param token:
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        # Only add a hybrid access token on auth step if asked for
        if 'token' not in (request.response_type or '').split():
            return token

        token.update(token_handler.create_token(request, refresh_token=False))
        return token

    def validate_grant_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        client_id = getattr(request, 'client_id', None)
        if not self.request_validator.validate_grant_type(client_id,
                                                          request.grant_type, request.client, request):
            log.debug('Unauthorized from %r (%r) access to grant type %s.',
                      request.client_id, request.client, request.grant_type)
            raise errors.UnauthorizedClientError(request=request)

    def validate_scopes(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if not request.scopes:
            request.scopes = utils.scope_to_list(request.scope) or utils.scope_to_list(
                self.request_validator.get_default_scopes(request.client_id, request))
        log.debug('Validating access to scopes %r for client %r (%r).',
                  request.scopes, request.client_id, request.client)
        if not self.request_validator.validate_scopes(request.client_id,
                                                      request.scopes, request.client, request):
            raise errors.InvalidScopeError(request=request)

    def validate_client_confidential(self, request):
        # If the client type is confidential or the client was issued client
        # credentials (or assigned other authentication requirements), the
        # client MUST authenticate with the authorization server as described
        # in Section 3.2.1.
        # https://tools.ietf.org/html/rfc6749#section-3.2.1
        log.debug('Authenticating confidential client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        if request.client is None or \
            not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        if not request.client_id:
            request.client_id = request.client.client_id
        elif request.client_id != request.client.client_id:
            raise errors.ServerError('Discrepency found between client identifier')

    def validate_client_public(self, request):
        # REQUIRED, if the client is not authenticating with the
        # authorization server as described in Section 3.2.1.
        # https://tools.ietf.org/html/rfc6749#section-3.2.1
        log.debug('Authenticating public client, %r.', request)
        if not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        if request.client is None or \
            not hasattr(request.client, 'client_id'):
            raise NotImplementedError('authenticate_client_id must set the '
                                      'request.client attribute to a client '
                                      'object with a client_id attribute.')

        if not request.client_id:
            request.client_id = request.client.client_id
        elif request.client_id != request.client.client_id:
            raise errors.ServerError('Discrepency found between client identifier')

    def validate_client_authentication(self, request):
        """Raise on failed client authentication."""
        # Handles confidential clients
        if self.request_validator.client_authentication_required(request):
            self.validate_client_confidential(request)
        # Handles public clients
        else:
            self.validate_client_public(request)

    def prepare_authorization_response(self, request, token, headers, body, status):
        """Place token according to response mode.

        Base classes can define a default response mode for their authorization
        response by overriding the static `default_response_mode` member.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token:
        :param headers:
        :param body:
        :param status:
        """
        self._validate_response_mode(request)

        if request.response_type == 'none':
            state = token.get('state', None)
            response = {'state': state} if state else {}
        else:
            response = dict(token)

        response_mode = self._effective_response_mode(request)
        if response_mode in jarm.JARM_RESPONSE_MODES:
            jwt_response = self._prepare_jarm_response(request, response)
            return self._format_jarm_response(
                request, jwt_response, headers, body, status)

        token_items = response.items()
        if response_mode == 'query':
            headers['Location'] = add_params_to_uri(
                request.redirect_uri, token_items, fragment=False)
            return headers, body, status

        if response_mode == 'fragment':
            headers['Location'] = add_params_to_uri(
                request.redirect_uri, token_items, fragment=True)
            return headers, body, status

        raise NotImplementedError(
            'Subclasses must set a valid default_response_mode')

    def _effective_response_mode(self, request):
        """Resolve the ``jwt`` shortcut to a concrete JARM response mode."""
        response_mode = request.response_mode
        if response_mode == jarm.JWT:
            return "{}.jwt".format(self.default_response_mode)
        return response_mode

    def _prepare_authorization_error_response(self, request, error,
                                              default_fragment):
        """Format an authorization error using the requested response mode."""
        response_mode = self._effective_response_mode(request)
        if response_mode in jarm.JARM_RESPONSE_MODES:
            jwt_response = self._prepare_jarm_response(
                request, dict(error.twotuples))
            return self._format_jarm_response(
                request, jwt_response, {}, None, 302)

        # Preserve the historical fallback behavior for response modes a
        # subclass supports as its default but does not implement here.
        fragment = (response_mode != "query" if default_fragment
                    else response_mode == "fragment")
        redirect_uri = add_params_to_uri(
            request.redirect_uri, error.twotuples, fragment=fragment)
        return {'Location': redirect_uri}, None, 302

    def _prepare_jarm_response(self, request, response):
        """Return a signed JARM JWT for the authorization response."""
        response = dict(response)

        # A validator may take full control of signing the response.
        for method_name in ('get_jarm_response', 'create_jarm_response'):
            get_response = getattr(
                self.request_validator, method_name, None)
            if callable(get_response):
                signed = get_response(dict(response), request)
                if isinstance(signed, (str, bytes)):
                    return self._as_jarm_jwt(signed)
                if isinstance(signed, dict):
                    response.update(signed)

        finalize = getattr(
            self.request_validator, 'finalize_jarm_response', None)
        sign = getattr(self.request_validator, 'sign_jarm_response', None)

        try:
            issuer = self._get_jarm_issuer(request)
        except jarm.JARMError as exc:
            # Some validators finalize the complete response themselves and
            # do not expose an issuer separately.
            for hook in (finalize, sign):
                if callable(hook):
                    signed = hook(dict(response), request)
                    if isinstance(signed, (str, bytes)):
                        return self._as_jarm_jwt(signed)
                    if isinstance(signed, dict):
                        response.update(signed)
            if not isinstance(response.get('iss'), str):
                raise exc
            issuer = response['iss']

        claims = jarm.create_jarm_claims(
            response,
            issuer,
            request.client_id,
            expires_in=self._get_jarm_expires_in(request),
        )

        # Alternatively, a validator may only implement signing of claims.
        if callable(finalize):
            signed = finalize(dict(claims), request)
            if isinstance(signed, (str, bytes)):
                return self._as_jarm_jwt(signed)
            if isinstance(signed, dict):
                claims = signed

        if callable(sign):
            signed = sign(dict(claims), request)
            if isinstance(signed, (str, bytes)):
                return self._as_jarm_jwt(signed)
            if isinstance(signed, dict):
                claims = signed

        key = self._get_jarm_signing_key(request)
        if key is None:
            raise NotImplementedError(
                "A JARM response requires request_validator."
                "get_jarm_response(), finalize_jarm_response(), "
                "sign_jarm_response(), or get_jarm_signing_key().")

        return jarm.sign_jarm_response(
            claims,
            key,
            algorithm=self._get_jarm_signing_alg(request),
            issuer=issuer,
            audience=request.client_id,
        )

    @staticmethod
    def _as_jarm_jwt(value):
        return value.decode('utf-8') if isinstance(value, bytes) else value

    def _format_jarm_response(self, request, jwt_response, headers, body, status):
        """Place a signed JARM JWT according to the response mode."""
        response_mode = self._effective_response_mode(request)
        if response_mode == jarm.QUERY_JWT:
            headers['Location'] = add_params_to_uri(
                request.redirect_uri,
                [('response', jwt_response)],
                fragment=False,
            )
            return headers, body, status

        if response_mode == jarm.FRAGMENT_JWT:
            headers['Location'] = add_params_to_uri(
                request.redirect_uri,
                [('response', jwt_response)],
                fragment=True,
            )
            return headers, body, status

        if response_mode == jarm.FORM_POST_JWT:
            headers.update({
                'Content-Type': 'text/html;charset=UTF-8',
                'Cache-Control': 'no-cache, no-store',
                'Pragma': 'no-cache',
            })
            action = html.escape(request.redirect_uri or '', quote=True)
            value = html.escape(jwt_response, quote=True)
            html_body = (
                '<html>\n'
                '<head><title>Submit This Form</title></head>\n'
                '<body onload="javascript:document.forms[0].submit()">\n'
                '<form method="post" action="{}">\n'
                '<input type="hidden" name="response" value="{}"/>\n'
                '</form>\n'
                '</body>\n'
                '</html>'
            ).format(action, value)
            return headers, html_body, 200

        raise NotImplementedError(
            'Subclasses must set a valid default_response_mode')

    def _get_jarm_expires_in(self, request):
        expires_in = getattr(request, 'jarm_response_expires_in', None)
        if expires_in is None:
            expires_in = getattr(request, 'jarm_expires_in', None)
        if expires_in is None:
            expires_in = getattr(
                self, 'jarm_expires_in', self.jarm_response_expires_in)
        if callable(expires_in):
            expires_in = expires_in(request)
        return expires_in

    def _get_jarm_issuer(self, request):
        for value in (
                getattr(self, 'jarm_issuer', None),
                getattr(self, 'issuer', None),
                getattr(request, 'jarm_issuer', None),
                getattr(request, 'issuer', None)):
            if isinstance(value, str) and value:
                return value

        for method_name in ('get_jarm_issuer', 'get_issuer'):
            get_issuer = getattr(
                self.request_validator, method_name, None)
            if callable(get_issuer):
                value = get_issuer(request)
                if isinstance(value, str) and value:
                    return value

        for attr_name in ('issuer', 'jarm_issuer'):
            value = getattr(self.request_validator, attr_name, None)
            if isinstance(value, str) and value:
                return value

        raise jarm.JARMError(
            "A JARM response requires an issuer. Set request.issuer, "
            "grant jarm_issuer, or implement get_jarm_issuer().")

    def _get_jarm_signing_key(self, request):
        for value in (
                getattr(self, 'jarm_signing_key', None),
                getattr(self, 'jarm_key', None),
                getattr(request, 'jarm_signing_key', None),
                getattr(request, 'jarm_key', None)):
            if self._is_jarm_signing_key(value):
                return value

        for method_name in ('get_jarm_signing_key', 'get_jarm_key'):
            get_key = getattr(
                self.request_validator, method_name, None)
            if callable(get_key):
                try:
                    value = get_key(request.client_id, request)
                except TypeError:
                    value = get_key(request)
                if self._is_jarm_signing_key(value):
                    return value

        for attr_name in ('jarm_signing_key', 'jarm_key'):
            value = getattr(self.request_validator, attr_name, None)
            if self._is_jarm_signing_key(value):
                return value

        return None

    @staticmethod
    def _is_jarm_signing_key(value):
        if value is None:
            return False
        if isinstance(value, (str, bytes, dict)):
            return True
        module = type(value).__module__
        return module.startswith(('cryptography.', 'jwt.'))

    def _get_jarm_signing_alg(self, request):
        for value in (
                getattr(self, 'jarm_signing_alg', None),
                getattr(self, 'jarm_algorithm', None),
                getattr(request, 'jarm_signing_alg', None),
                getattr(request, 'jarm_algorithm', None)):
            if isinstance(value, str) and value:
                return value

        for method_name in (
                'get_jarm_signing_alg',
                'get_jarm_signing_algorithm',
                'get_jarm_algorithm'):
            get_alg = getattr(
                self.request_validator, method_name, None)
            if callable(get_alg):
                try:
                    value = get_alg(request.client_id, request)
                except TypeError:
                    value = get_alg(request)
                if isinstance(value, str) and value:
                    return value

        for attr_name in ('jarm_signing_alg', 'jarm_algorithm'):
            value = getattr(self.request_validator, attr_name, None)
            if isinstance(value, str) and value:
                return value

        return 'RS256'

    def _validate_response_mode(self, request):
        """Reject unsupported response modes and apply the default one.

        This must run before any error is redirected to the client, since
        the response mode determines how error parameters are returned.
        An unsupported response mode is a fatal error: the response cannot
        be returned in the requested format, and one in another format may
        not be understood by the client.

        The grant's ``default_response_mode`` is always accepted.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if (request.response_mode
                and request.response_mode not in self._response_modes
                and request.response_mode != self.default_response_mode):
            log.debug('Unsupported response mode %s for client %s.',
                      request.response_mode, request.client_id)
            raise errors.UnsupportedResponseModeError(request=request)
        request.response_mode = request.response_mode or self.default_response_mode

    def _get_default_headers(self):
        """Create default headers for grant responses."""
        return {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }

    def _handle_redirects(self, request):
        if request.redirect_uri is not None:
            request.using_default_redirect_uri = False
            log.debug('Using provided redirect_uri %s', request.redirect_uri)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(request=request)

            # The authorization server MUST verify that the redirection URI
            # to which it will redirect the access token matches a
            # redirection URI registered by the client as described in
            # Section 3.1.2.
            # https://tools.ietf.org/html/rfc6749#section-3.1.2
            if not self.request_validator.validate_redirect_uri(
                    request.client_id, request.redirect_uri, request):
                raise errors.MismatchingRedirectURIError(request=request)
        else:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(
                request.client_id, request)
            request.using_default_redirect_uri = True
            log.debug('Using default redirect_uri %s.', request.redirect_uri)
            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(request=request)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(request=request)

    def _create_cors_headers(self, request):
        """If CORS is allowed, create the appropriate headers."""
        if 'origin' not in request.headers:
            return {}

        origin = request.headers['origin']
        if not is_secure_transport(origin):
            log.debug('Origin "%s" is not HTTPS, CORS not allowed.', origin)
            return {}
        elif not self.request_validator.is_origin_allowed(
            request.client_id, origin, request):
            log.debug('Invalid origin "%s", CORS not allowed.', origin)
            return {}
        else:
            log.debug('Valid origin "%s", injecting CORS headers.', origin)
            return {'Access-Control-Allow-Origin': origin}
