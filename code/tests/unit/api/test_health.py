from http import HTTPStatus
from pytest import fixture
from unittest import mock
from requests.exceptions import SSLError
from tests.unit.api.utils import headers
from tests.unit.conftest import cyberprotect_api_response

from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
    EXPECTED_RESPONSE_SSL_ERROR,
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(route, client, valid_jwt):
    response = client.post(route, headers=headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK


def test_health_call_404(route, client, cyberprotect_api_request,
                         valid_jwt):
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(status_code=HTTPStatus.NOT_FOUND)
    ]
    response = client.post(route, headers=headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_health_call_500(route, client, valid_jwt, cyberprotect_api_request):
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                                  payload=CYBERPROTECT_500_ERROR_RESPONSE_MOCK)
    ]
    response = client.post(route, headers=headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR


def test_health_call_ssl_error(route, client, cyberprotect_api_request,
                               valid_jwt):
    mock_exception = mock.MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        SSLError(mock_exception)
    ]

    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_SSL_ERROR
