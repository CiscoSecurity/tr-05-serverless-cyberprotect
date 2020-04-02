from version import VERSION


class Config:
    VERSION = VERSION

    CYBERPROTECT_API_URL = \
        'https://threatscore.cyberprotect.fr/api/score/{observable}'

    CYBERPROTECT_HEALTH_CHECK_IP = '127.0.0.100'

    CYBERPROTECT_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
    }
