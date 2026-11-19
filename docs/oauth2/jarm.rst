JWT Secured Authorization Response Mode (JARM)
===============================================

OAuthLib supports the JARM response modes ``query.jwt``, ``fragment.jwt``
and ``form_post.jwt``.  The ``jwt`` shortcut selects ``query.jwt`` for
authorization code responses and ``fragment.jwt`` for responses that default
to the fragment, such as implicit and hybrid responses.

The signed authorization response contains the normal response parameters
(``code``, ``state``, ``access_token``, error parameters, and so on) together
with the required ``iss``, ``aud`` and ``exp`` claims.  ``iat`` is also added.
The JWT is returned as the ``response`` parameter; no other authorization
response parameters are placed in the URI.

Server configuration
--------------------

JARM signing requires PyJWT, which is available through the
``signedtoken`` extra::

    pip install oauthlib[signedtoken]

A validator can either sign the response itself:

.. code-block:: python

    from oauthlib.oauth2 import sign_jarm_response

    def get_jarm_response(self, response, request):
        return sign_jarm_response(
            response,
            private_key,
            algorithm="RS256",
            issuer="https://authorization.example",
            audience=request.client_id,
        )

or provide a key and let OAuthLib create and sign the standard claims:

.. code-block:: python

    def get_jarm_issuer(self, request):
        return "https://authorization.example"

    def get_jarm_signing_key(self, client_id, request):
        return private_key

    def get_jarm_signing_alg(self, client_id, request):
        return "RS256"

``finalize_jarm_response`` and ``sign_jarm_response`` validator hooks are also
available for applications that split claim construction from signing.

Client validation
-----------------

The client must know the expected issuer and a key for signature verification.
These can be supplied to the client or directly to the parsing method:

.. code-block:: python

    client = WebApplicationClient(
        "client-id",
        issuer="https://authorization.example",
        jarm_key=public_key,
        jarm_algorithms=["RS256"],
    )
    response = client.parse_request_uri_response(
        callback_uri,
        state=expected_state,
    )

The client verifies the JWS signature and checks ``iss``, ``aud`` and ``exp``
before returning any response parameter.  Invalid or expired responses raise
``JARMValidationError``.
