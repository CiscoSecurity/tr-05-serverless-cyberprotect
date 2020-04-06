import json
from typing import Optional
from http import HTTPStatus

from flask import request, current_app, jsonify

from api.errors import (
    CyberprotectNotFoundError,
    CyberprotectUnexpectedError,
    BadRequestError
)


def url_for(observable) -> Optional[str]:

    return current_app.config['CYBERPROTECT_API_URL'].format(
        observable=observable,
    )


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
    return jsonify({'errors': [error]})


def get_response_data(response):

    if response.ok:
        return response.json()

    else:
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise CyberprotectNotFoundError()

        else:
            raise CyberprotectUnexpectedError(response.json())
