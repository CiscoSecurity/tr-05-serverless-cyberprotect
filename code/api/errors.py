
INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
INTERNAL = 'internal error'
KEY_ERROR = 'key error'
AUTH_ERROR = 'authorization error'


class TRError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class CyberprotectNotFoundError(TRError):
    def __init__(self):

        super().__init__(
            code=NOT_FOUND,
            message='The Cyberprotect not found'
        )


class CyberprotectServiceUnavailableError(TRError):
    def __init__(self):

        super().__init__(
            code=NOT_FOUND,
            message='The Cyberprotect is not available now.'
        )


class CyberprotectUnexpectedError(TRError):
    def __init__(self, payload):
        error_payload = payload.get('error', {})

        super().__init__(
            code=UNKNOWN,
            message=error_payload.get('message', None) or error_payload.get(
                'details', None)
        )


class CyberprotectKeyError(TRError):
    def __init__(self):

        super().__init__(
            code=KEY_ERROR,
            message='The data structure of Cyberprotect has changed.'
                    ' The module is broken.'
        )


class CyberprotectSSLError(TRError):
    def __init__(self, error):
        message = getattr(
            error.args[0].reason.args[0], 'verify_message', ''
        ) or error.args[0].reason.args[0].args[0]

        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class BadRequestError(TRError):
    def __init__(self, error_message):
        super().__init__(
            INVALID_ARGUMENT,
            error_message
        )


class AuthorizationError(TRError):
    def __init__(self, message):

        super().__init__(
            AUTH_ERROR,
            f"Authorization failed: {message}"
        )


class WatchdogError(TRError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )
