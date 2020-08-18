from http import HTTPStatus

from pytest import fixture
from unittest import mock
from requests.exceptions import SSLError

from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    CYBERPROTECT_HEALTH_RESPONSE_MOCK,
    CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
    CYBERPROTECT_404_ERROR_RESPONSE_MOCK,
    EXPECTED_RESPONSE_SSL_ERROR
)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def cyberprotect_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def cyberprotect_api_response(*, ok, status_error=None):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    if ok:
        payload = CYBERPROTECT_HEALTH_RESPONSE_MOCK

    else:
        if status_error == HTTPStatus.NOT_FOUND:
            payload = CYBERPROTECT_404_ERROR_RESPONSE_MOCK
            mock_response.status_code = HTTPStatus.NOT_FOUND
        elif status_error == HTTPStatus.INTERNAL_SERVER_ERROR:
            payload = CYBERPROTECT_500_ERROR_RESPONSE_MOCK
            mock_response.status_code = HTTPStatus.INTERNAL_SERVER_ERROR

    mock_response.json = lambda: payload

    return mock_response


def test_health_call_success(route, client):
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK


def test_health_call_404(route, client, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(ok=False, status_error=HTTPStatus.NOT_FOUND)
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_health_call_500(route, client, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(
            ok=False, status_error=HTTPStatus.INTERNAL_SERVER_ERROR)
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR


def test_enrich_call_ssl_error(route, client, cyberprotect_api_request):
    mock_exception = mock.MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    cyberprotect_api_request.side_effect = SSLError(mock_exception)

    response = client.post(route)

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_SSL_ERROR
