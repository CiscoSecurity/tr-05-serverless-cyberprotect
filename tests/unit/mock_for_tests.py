CYBERPROTECT_HEALTH_RESPONSE_MOCK = {
    "scores": [[]],
    "types": ["Unknown"],
    "signature": "ff918fa60fd5b8a7abc6950307cf96e248667f191b2ac2ee0"
}

CYBERPROTECT_RESPONSE = {
    "geo": {
        "country": {
            "code": "AU",
            "name": "Australia"
        }
    },
    "signature":
        "f9e779c8cefd81cbc3824564e7e0aec121547eeaaf210d5b7a3442f02761b940",
    "data": "1.1.1.1",
    "types": [
        "ip"
    ],
    "version": 16779232,
    "firstSeen": "2018-10-01",
    "lastSeen": "2020-04-03T10:15:17.281Z",
    "sources": 1,
    "scores": [
        {
            "date": "2020-04-03T10:15:17.281Z",
            "score": 0.3397058823529412,
            "confidence": None,
            "level": "suspicious",
            "details": [
                {
                    "date": "2020-04-03T10:15:17.281Z",
                    "engineId": "0092293a2e6b3ada22c681617520e124",
                    "engineConfidence": None,
                    "level": "safe",
                    "score": 0
                },
                {
                    "date": "2020-04-03T10:15:17.281Z",
                    "engineId": "f06549a927164a3f2e336977a41794c8",
                    "engineConfidence": None,
                    "level": "malicious",
                    "score": 0.9
                },
                {
                    "date": "2020-04-03T10:15:17.281Z",
                    "engineId": "558a885ad3bb9fe8c84629c39ea64431",
                    "engineConfidence": None,
                    "level": "suspicious",
                    "score": 0.5
                },
                {
                    "date": "2020-04-03T10:15:17.281Z",
                    "engineId": "a8451f72cbe670c3d971157a2b73be0e",
                    "engineConfidence": None,
                    "level": "safe",
                    "score": 0.175
                }
            ]
        }
    ]
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

EXPECTED_RESPONSE_DELIBERATE = {
    'data': {
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'type': 'verdict',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                }
            ]
        }
    }
}


EXPECTED_RESPONSE_OBSERVE = {
    'data': {
        'judgements': {
            'count': 4,
            'docs': [
                {
                    'confidence': 'Medium',
                    'disposition': 1,
                    'disposition_name': 'Clean',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'priority': 85,
                    'reason': 'Engine: 0092293a2e6b3ada22c681617520e124',
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'Threatscore Cyberprotect',
                    'source_uri': 'https://threatscore.cyberprotect.fr/'
                                  'search?query=1.1.1.1',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                },
                {
                    'confidence': 'Medium',
                    'disposition': 2,
                    'disposition_name': 'Malicious',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'priority': 85,
                    'reason': 'Engine: f06549a927164a3f2e336977a41794c8',
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'Threatscore Cyberprotect',
                    'source_uri': 'https://threatscore.cyberprotect.fr/'
                                  'search?query=1.1.1.1',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                },
                {
                    'confidence': 'Medium',
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'priority': 85,
                    'reason': 'Engine: 558a885ad3bb9fe8c84629c39ea64431',
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'Threatscore Cyberprotect',
                    'source_uri': 'https://threatscore.cyberprotect.fr/'
                                  'search?query=1.1.1.1',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                },
                {
                    'confidence': 'Medium',
                    'disposition': 1,
                    'disposition_name': 'Clean',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'priority': 85,
                    'reason': 'Engine: a8451f72cbe670c3d971157a2b73be0e',
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'Threatscore Cyberprotect',
                    'source_uri': 'https://threatscore.cyberprotect.fr/'
                                  'search?query=1.1.1.1',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                }
            ]
        },
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'type': 'verdict',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                }
            ]
        }
    }
}

EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1 = {
    'data': {
        'judgements': {
            'count': 1,
            'docs': [
                {
                    'confidence': 'Medium',
                    'disposition': 1,
                    'disposition_name': 'Clean',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'priority': 85,
                    'reason': 'Engine: 0092293a2e6b3ada22c681617520e124',
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'Threatscore Cyberprotect',
                    'source_uri':
                        'https://threatscore.cyberprotect.fr/'
                        'search?query=1.1.1.1',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                }
            ]
        },
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
                    'observable': {
                        'type': 'ip',
                        'value': '1.1.1.1'
                    },
                    'type': 'verdict',
                    'valid_time': {
                        'end_time': '2020-04-10T10:15:17.281000Z',
                        'start_time': '2020-04-03T10:15:17.281000Z'
                    }
                }
            ]
        }
    }
}
