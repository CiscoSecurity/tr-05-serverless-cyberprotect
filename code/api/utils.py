from functools import wraps

import jwt
import json
import requests

from typing import Optional
from http import HTTPStatus
from flask import request, current_app, jsonify, g
from requests.exceptions import ConnectionError, InvalidURL, SSLError
from jwt import InvalidSignatureError, InvalidAudienceError, DecodeError
from api.errors import (
    CyberprotectNotFoundError,
    CyberprotectUnexpectedError,
    BadRequestError,
    CyberprotectKeyError,
    CyberprotectSSLError,
    CyberprotectServiceUnavailableError
)

from api.errors import AuthorizationError

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWK_HOST_MISSING = ('jwk_host is missing in JWT payload. Make sure '
                    'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def url_for(observable) -> Optional[str]:

    return current_app.config['CYBERPROTECT_API_URL'].format(
        observable=observable,
    )


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0
    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_DEFAULT_ENTITIES_LIMIT']
    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_public_key(jwks_host, token):
    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
    }
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Get Authorization token and validate its signature
    against the application's secret key, .
    """

    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWK_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }

    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}
        ).get('jwks_host')
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        set_ctr_entities_limit(payload)
        return payload
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token():
    """
    Parse the incoming request's Authorization header and Validate it.
    """

    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None
    if error:
        raise BadRequestError(
            f'Invalid JSON payload received. {json.dumps(error)}.'
        )

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_error(error):
    data = {
        'errors': [error],
        'data': {}
    }

    if g.get('bundle'):
        data['data'] = g.bundle.json()

    if not data['data']:
        data.pop('data')

    return jsonify(data)


def get_response_data(response):
    data = response.json()

    if response.ok:
        return data

    else:
        if response.status_code == HTTPStatus.NOT_FOUND:
            # 404 is returned for both wrong url and no data for observable
            if (
                data and "Observable not found"
                    in data.get('error', {}).get('message')
            ):
                return

            raise CyberprotectNotFoundError()

        elif response.status_code > HTTPStatus.INTERNAL_SERVER_ERROR:
            raise CyberprotectServiceUnavailableError()

        else:
            raise CyberprotectUnexpectedError(response.json())


def key_error_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except KeyError:
            raise CyberprotectKeyError
        return result
    return wrapper


def catch_ssl_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise CyberprotectSSLError(error)
    return wrapper
