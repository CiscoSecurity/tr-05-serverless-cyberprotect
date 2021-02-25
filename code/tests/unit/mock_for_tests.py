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

BROKEN_CYBERPROTECT_RESPONSE = {
    "scores": [
        {
            "level": "suspicious",
            "broken_date_key": "2020-04-03T10:15:17.281Z",
            "score": 0.3397058823529412,
            "details": [
                {
                    "broken_date_key": "2020-04-03T10:15:17.281Z",
                    "engineId": "0092293a2e6b3ada22c681617520e124",
                    "engineConfidence": None,
                    "level": "safe",
                    "score": 0
                },
                {
                    "broken_date_key": "2020-04-03T10:15:17.281Z",
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

EXPECTED_RESPONSE_KEY_ERROR = {
    'errors': [
        {
            'code': 'key error',
            'message': 'The data structure of Cyberprotect has changed. The '
                       'module is broken.',
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


EXPECTED_RESPONSE_SSL_ERROR = {
    'errors': [
        {
            'code': 'unknown',
            'message': 'Unable to verify SSL certificate: self signed '
                       'certificate',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
  'keys': [
    {
      'kty': 'RSA',
      'n': 'tSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
           'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
           'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
           '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
           'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
           '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
           'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
           'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
           'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
           'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
           'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
           '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
           'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
           'k3jNdVM',
      'e': 'AQAB',
      'alg': 'RS256',
      'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
      'use': 'sig'
    }
  ]
}

RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'pSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
