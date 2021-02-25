from unittest import mock
from pytest import fixture
from http import HTTPStatus
from requests.exceptions import SSLError
from tests.unit.api.utils import headers
from tests.unit.conftest import cyberprotect_api_response
from tests.unit.mock_for_tests import (
    CYBERPROTECT_RESPONSE,
    CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
    CYBERPROTECT_404_ERROR_RESPONSE_MOCK,
    EXPECTED_RESPONSE_500_ERROR,
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_DELIBERATE,
    EXPECTED_RESPONSE_OBSERVE,
    EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1,
    BROKEN_CYBERPROTECT_RESPONSE,
    EXPECTED_RESPONSE_KEY_ERROR,
    EXPECTED_RESPONSE_SSL_ERROR,
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
)


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(route, client, invalid_json):
    response = client.post(route, json=invalid_json)
    assert response.status_code == HTTPStatus.OK


@fixture(scope='module')
def valid_json_multiple():
    return [
        {'type': 'ip', 'value': '1.1.1.1'},
        {'type': 'ip', 'value': '0.0.0.0'},
    ]


@fixture(scope='module')
def expected_payload(route, client):

    payload = None

    if route.startswith('/deliberate'):

        payload = EXPECTED_RESPONSE_DELIBERATE

    if route.startswith('/observe'):

        payload = EXPECTED_RESPONSE_OBSERVE

    return payload


def test_enrich_call_success(route, client, valid_json,
                             cyberprotect_api_request, expected_payload,
                             valid_jwt):
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(payload=CYBERPROTECT_RESPONSE)
    ]

    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)

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


def test_enrich_error_with_data(route, client, valid_json_multiple,
                                cyberprotect_api_request, expected_payload,
                                valid_jwt):
    cyberprotect_api_request.side_effect = (
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(payload=CYBERPROTECT_RESPONSE),
        cyberprotect_api_response(
            payload=CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR)
    )

    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json_multiple)

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()

    if route == '/observe/observables':
        judgements = data['data']['judgements']
        assert judgements['count'] == 4
        assert judgements['docs'][0].pop('id')
        assert judgements['docs'][1].pop('id')
        assert judgements['docs'][2].pop('id')
        assert judgements['docs'][3].pop('id')

    expected_response = {}
    expected_response.update(expected_payload)
    expected_response.update(EXPECTED_RESPONSE_500_ERROR)

    assert data == expected_response


def test_enrich_call_success_limit_1(route, client, valid_json,
                                     cyberprotect_api_request,
                                     valid_jwt):

    if route == '/observe/observables':
        cyberprotect_api_request.side_effect = [
            cyberprotect_api_response(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            ),
            cyberprotect_api_response(payload=CYBERPROTECT_RESPONSE)
        ]

        response = client.post(route, headers=headers(valid_jwt(
            ctr_entities_limit=1)), json=valid_json)

        assert response.status_code == HTTPStatus.OK

        data = response.get_json()

        if route == '/observe/observables':
            judgements = data['data']['judgements']
            assert judgements['count'] == 1
            assert judgements['docs'][0].pop('id')

        assert data == EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1


def test_enrich_call_with_key_error(route, client, valid_json,
                                    cyberprotect_api_request,
                                    valid_jwt):

    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(
            payload=BROKEN_CYBERPROTECT_RESPONSE)
    ]

    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_KEY_ERROR


def test_enrich_call_404(route, client, valid_json, cyberprotect_api_request,
                         valid_jwt):
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(
            payload=CYBERPROTECT_404_ERROR_RESPONSE_MOCK,
            status_code=HTTPStatus.NOT_FOUND)
    ]
    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_enrich_call_500(route, client, valid_json, cyberprotect_api_request,
                         valid_jwt):
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        cyberprotect_api_response(
            payload=CYBERPROTECT_500_ERROR_RESPONSE_MOCK,
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR)
    ]
    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR


def test_enrich_call_ssl_error(route, client, valid_json,
                               cyberprotect_api_request,
                               valid_jwt):
    mock_exception = mock.MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    cyberprotect_api_request.side_effect = [
        cyberprotect_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        SSLError(mock_exception)
    ]

    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_SSL_ERROR
