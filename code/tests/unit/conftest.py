import jwt
from app import app
from unittest import mock
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock
from tests.unit.mock_for_tests import PRIVATE_KEY

from api.errors import AUTH_ERROR


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY
    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            ctr_entities_limit=0,
            wrong_jwks_host=False,
    ):
        payload = {
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': ctr_entities_limit
        }

        if wrong_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='function')
def cyberprotect_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@fixture(scope='module')
def authorization_errors_expected_payload(route):
    def _make_payload_message(message):
        payload = {
            'errors': [
                {
                    'code': AUTH_ERROR,
                    'message': f'Authorization failed: {message}',
                    'type': 'fatal'
                }
            ]
        }
        return payload

    return _make_payload_message


def cyberprotect_api_response(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response
