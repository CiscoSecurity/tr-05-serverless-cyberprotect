from http import HTTPStatus

from pytest import fixture
from unittest import mock

from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    CYBERPROTECT_HEALTH_RESPONSE_MOCK,
    CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
    CYBERPROTECT_404_ERROR_RESPONSE_MOCK
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
        if status_error == 404:
            payload = CYBERPROTECT_404_ERROR_RESPONSE_MOCK
            mock_response.status_code = 404
        elif status_error == 500:
            payload = CYBERPROTECT_500_ERROR_RESPONSE_MOCK
            mock_response.status_code = 500

    mock_response.json = lambda: payload

    return mock_response


def test_health_call_success(route, client):
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK


def test_health_call_404(route, client, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(ok=False, status_error=404)
    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_health_call_500(route, client, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(ok=False, status_error=500)
    response = client.post(route)
    assert response.status_code == 200
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR
