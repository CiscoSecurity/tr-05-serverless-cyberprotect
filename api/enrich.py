from datetime import datetime, timedelta

import requests
from flask import Blueprint, current_app

from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data, url_for, get_response_data

enrich_api = Blueprint('enrich', __name__)


def validate_cyberprotect_output(cyberprotect_input):
    url = url_for(cyberprotect_input)
    return get_response_data(
        requests.get(url, headers=current_app.config['CYBERPROTECT_HEADERS'])
    )


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:

        obj['type'] = obj['type'].lower()

        # Get only supported types.
        if obj['type'] in current_app.config['CYBERPROTECT_OBSERVABLE_TYPES']:
            if obj in result:
                continue
            result.append(obj)

    return result


def get_cyberprotect_outputs(observables):
    # Return list of responses from Cyberprotect for all observables

    outputs = []
    for observable in observables:
        cyberprotect_output = validate_cyberprotect_output(
            observable['value'])

        cyberprotect_output['observable'] = observable
        outputs.append(cyberprotect_output)

    return outputs


def get_disposition(score):

    disposition = None
    disposition_name = None

    for d_name, borders in \
            current_app.config['CYBERPROTECT_SCORE_RELATIONS'].items():
        if borders[0] <= score <= borders[1]:
            disposition = current_app.config['CTIM_DISPOSITIONS'][d_name]
            disposition_name = d_name

    return disposition, disposition_name


def extract_verdicts(output, score):
    disposition, disposition_name = get_disposition(score['score'])

    start_time = datetime.strptime(score['date'], '%Y-%m-%dT%H:%M:%S.%fZ')
    end_time = start_time + timedelta(
        days=current_app.config['CTIM_VALID_DAYS_PERIOD'])

    valid_time = {
        'start_time': start_time.isoformat() + 'Z',
        'end_time': end_time.isoformat() + 'Z'
    }

    observable = {
        'value': output['observable']['value'],
        'type': output['observable']['type']
    }

    doc = {
        'observable': observable,
        'disposition': disposition,
        'disposition_name': disposition_name,
        'valid_time': valid_time,
        **current_app.config['CTIM_VERDICT_DEFAULTS']
    }

    return doc


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    cyberprotect_outputs = get_cyberprotect_outputs(observables)

    verdicts = []
    for output in cyberprotect_outputs:
        for score in output['scores']:
            # need to check because [[]] return in output if don't have scores
            if score:
                verdicts.append(extract_verdicts(output, score))

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    cyberprotect_outputs = get_cyberprotect_outputs(observables)

    verdicts = []
    for output in cyberprotect_outputs:
        for score in output['scores']:
            # need to check because [[]] return in output  if don't have scores
            if score:
                verdicts.append(extract_verdicts(output, score))

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
