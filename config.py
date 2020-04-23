import os

from version import VERSION


class Config:
    VERSION = VERSION

    CYBERPROTECT_API_URL = \
        'https://threatscore.cyberprotect.fr/api/score/{observable}'
    CYBERPROTECT_UI_URL = \
        'https://threatscore.cyberprotect.fr/search?query={observable}'

    CYBERPROTECT_HEADERS = {
        'User-Agent': ('Cisco Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>')
    }

    CYBERPROTECT_SOURCE_NAME = 'Threatscore Cyberprotect'

    CYBERPROTECT_HEALTH_CHECK_IP = '127.0.0.100'

    CYBERPROTECT_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
        'domain': 'Domain'
    }

    CYBERPROTECT_SCORE_RELATIONS = {
        'Clean': (0, 0.25),
        'Suspicious': (0.251, 0.5),
        'Malicious': (0.501, 1)
    }

    CTIM_SCHEMA_VERSION = '1.0.16'
    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }
    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'schema_version': CTIM_SCHEMA_VERSION,
        'source': CYBERPROTECT_SOURCE_NAME,
        'confidence': 'Medium',
        'priority': 85,
        'severity': 'Medium',
    }

    CTIM_DEFAULT_ENTITIES_LIMIT = 100
    CTIM_MAX_ENTITIES_LIMIT = \
        int(os.environ.get('CTR_ENTITIES_LIMIT', CTIM_DEFAULT_ENTITIES_LIMIT))

    CTIM_VALID_DAYS_PERIOD = 7

    CTIM_DISPOSITIONS = {
        'Clean': 1,
        'Suspicious': 3,
        'Malicious': 2,
        'Unknown': 5
    }
