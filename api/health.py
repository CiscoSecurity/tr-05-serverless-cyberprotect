import requests
from flask import Blueprint, current_app

from api.utils import jsonify_data, url_for, get_response_data

health_api = Blueprint('health', __name__)


def check_health_cyberprotect_api():
    url = url_for(current_app.config['CYBERPROTECT_HEALTH_CHECK_IP'])
    return get_response_data(
        requests.get(url, headers=current_app.config['CYBERPROTECT_HEADERS'])
    )


@health_api.route('/health', methods=['POST'])
def health():
    check_health_cyberprotect_api()
    return jsonify_data({'status': 'ok'})
