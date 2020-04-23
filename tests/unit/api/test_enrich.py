from http import HTTPStatus

from pytest import fixture
from unittest import mock

from tests.unit.mock_for_tests import (
    CYBERPROTECT_RESPONSE,
    CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
    CYBERPROTECT_404_ERROR_RESPONSE_MOCK,
    EXPECTED_RESPONSE_500_ERROR,
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_DELIBERATE,
    EXPECTED_RESPONSE_OBSERVE,
    EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1
)


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'


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
        payload = CYBERPROTECT_RESPONSE

    else:
        if status_error == HTTPStatus.NOT_FOUND:
            payload = CYBERPROTECT_404_ERROR_RESPONSE_MOCK
            mock_response.status_code = HTTPStatus.NOT_FOUND
        elif status_error == HTTPStatus.INTERNAL_SERVER_ERROR:
            payload = CYBERPROTECT_500_ERROR_RESPONSE_MOCK
            mock_response.status_code = HTTPStatus.INTERNAL_SERVER_ERROR

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(route, client, invalid_json):
    response = client.post(route, json=invalid_json)
    assert response.status_code == HTTPStatus.OK


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@fixture(scope='module')
def expected_payload(route, client):

    payload = None

    if route.startswith('/deliberate'):

        payload = EXPECTED_RESPONSE_DELIBERATE

    if route.startswith('/observe'):

        payload = EXPECTED_RESPONSE_OBSERVE

    return payload


def test_enrich_call_success(route, client, valid_json,
                             cyberprotect_api_request, expected_payload):
    cyberprotect_api_request.return_value = cyberprotect_api_response(ok=True)

    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()

    if route == '/observe/observables':
        judgements = data['data']['judgements']
        assert judgements['count'] == 4
        assert judgements['docs'][0].pop('id')
        assert judgements['docs'][1].pop('id')
        assert judgements['docs'][2].pop('id')
        assert judgements['docs'][3].pop('id')

    assert data == expected_payload


def test_enrich_call_success_limit_1(route, client, valid_json,
                                     cyberprotect_api_request):

    if route == '/observe/observables':
        cyberprotect_api_request.return_value = \
            cyberprotect_api_response(ok=True)

        client.application.config['CTR_ENTITIES_LIMIT'] = 1

        response = client.post(route, json=valid_json)

        assert response.status_code == HTTPStatus.OK

        data = response.get_json()

        if route == '/observe/observables':
            judgements = data['data']['judgements']
            assert judgements['count'] == 1
            assert judgements['docs'][0].pop('id')

        assert data == EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1


def test_enrich_call_404(route, client, valid_json, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(ok=False, status_error=HTTPStatus.NOT_FOUND)
    response = client.post(route, json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_enrich_call_500(route, client, valid_json, cyberprotect_api_request):
    cyberprotect_api_request.return_value = \
        cyberprotect_api_response(
            ok=False, status_error=HTTPStatus.INTERNAL_SERVER_ERROR)
    response = client.post(route, json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR
