from version import VERSION


class Config:
    VERSION = VERSION

    CYBERPROTECT_API_URL = \
        'https://threatscore.cyberprotect.fr/api/score/{observable}'

    CYBERPROTECT_SOURCE_NAME = 'Threatscore Cyberprotect'

    CYBERPROTECT_HEALTH_CHECK_IP = '127.0.0.100'

    CYBERPROTECT_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
    }

    CYBERPROTECT_SCORE_RELATIONS = {
        'Unknown': (0, 0),
        'Clean': (0.001, 0.25),
        'Suspicious': (0.251, 0.5),
        'Malicious': (0.501, 1)
    }

    CTIM_SCHEMA_VERSION = '1.0.16'
    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }

    CTIM_VALID_DAYS_PERIOD = 7

    CTIM_DISPOSITIONS = {
        'Clean': 1,
        'Suspicious': 3,
        'Malicious': 2,
        'Unknown': 5
    }
