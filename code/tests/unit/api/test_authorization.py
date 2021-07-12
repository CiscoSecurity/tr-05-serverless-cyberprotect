from http import HTTPStatus

from pytest import fixture
from requests.exceptions import InvalidURL, ConnectionError

from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWKS_HOST,
    JWK_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)
from .utils import headers
from ..conftest import cyberprotect_api_response
from ..mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


def routes():
    yield '/health'
    yield '/observe/observables'
    yield '/deliberate/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        NO_AUTH_HEADER
    )


def test_call_with_wrong_auth_type(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(), auth_type='not')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE
    )


def test_call_with_wrong_jwks_host(
        route, client, valid_json, valid_jwt, cyberprotect_api_request,
        authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        cyberprotect_api_request.side_effect = error()

        response = client.post(
            route, json=valid_json, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


def test_call_with_missing_jwks_host(
        route, client, valid_json, valid_jwt, cyberprotect_api_request,
        authorization_errors_expected_payload,
):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(wrong_jwks_host=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWK_HOST_MISSING
    )


def test_call_with_wrong_key(
        route, client, valid_json, valid_jwt, cyberprotect_api_request,
        authorization_errors_expected_payload,
):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(
            payload=RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
        )

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt())
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )


def test_call_with_wrong_jwt_structure(
        route, client, valid_json, cyberprotect_api_request,
        authorization_errors_expected_payload,
):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers('valid_jwt()')
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


def test_call_with_wrong_audience(
        route, client, valid_json, valid_jwt, cyberprotect_api_request,
        authorization_errors_expected_payload,
):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(aud='wrong_aud'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


def test_call_with_wrong_kid(
        route, client, valid_json, valid_jwt, cyberprotect_api_request,
        authorization_errors_expected_payload,
):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(kid='wrong_kid'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        KID_NOT_FOUND
    )
