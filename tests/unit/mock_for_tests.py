CYBERPROTECT_HEALTH_RESPONSE_MOCK = {
    "scores": [[]],
    "types": ["Unknown"],
    "signature": "ff918fa60fd5b8a7abc6950307cf96e248667f191b2ac2ee0"
}

CYBERPROTECT_500_ERROR_RESPONSE_MOCK = {
    "error": {
        "type": "Server Error",
        "code": "500",
        "message": "Internal Error"
    }
}

CYBERPROTECT_404_ERROR_RESPONSE_MOCK = {
    "error": {
        "type": "Client Error",
        "code": "404",
        "message": "Not Found"
    }
}

EXPECTED_RESPONSE_404_ERROR = {
    'errors': [
        {
            'code': 'not found',
            'message': 'The Cyberprotect not found',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_500_ERROR = {
    'errors': [
        {
            'code': 'unknown',
            'message': 'Internal Error',
            'type': 'fatal'
        }
    ]
}
