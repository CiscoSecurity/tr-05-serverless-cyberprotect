from datetime import datetime, timedelta
from uuid import uuid4

import requests
from flask import Blueprint, current_app, g

from api.bundle import Bundle
from api.schemas import ObservableSchema
from api.utils import (
    get_jwt,
    get_json,
    jsonify_data,
    url_for,
    get_response_data,
    key_error_handler,
    catch_ssl_errors
)

enrich_api = Blueprint('enrich', __name__)


@catch_ssl_errors
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


def get_cyberprotect_outputs(observable):
    # Return list of responses from Cyberprotect for all observables

    cyberprotect_output = validate_cyberprotect_output(
        observable['value'])

    if cyberprotect_output:
        cyberprotect_output['observable'] = observable

    return cyberprotect_output


def get_disposition(score):
    if score < 0:
        return 1, 'Clean'
    else:
        for d_name, borders in \
                current_app.config['CYBERPROTECT_SCORE_RELATIONS'].items():
            if borders[0] <= score <= borders[1]:
                return current_app.config['CTIM_DISPOSITIONS'][d_name], d_name


@key_error_handler
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


@key_error_handler
def extract_judgement(output, details):
    disposition, disposition_name = get_disposition(details['score'])

    start_time = datetime.strptime(details['date'], '%Y-%m-%dT%H:%M:%S.%fZ')
    end_time = start_time + timedelta(
        days=current_app.config['CTIM_VALID_DAYS_PERIOD'])

    valid_time = {
        'start_time': start_time.isoformat(timespec='microseconds') + 'Z',
        'end_time': end_time.isoformat(timespec='microseconds') + 'Z',
    }

    observable = {
        'value': output['observable']['value'],
        'type': output['observable']['type']
    }

    judgement_id = f'transient:judgement-{uuid4()}'

    doc = {
        'id': judgement_id,
        'observable': observable,
        'disposition': disposition,
        'disposition_name': disposition_name,
        'valid_time': valid_time,
        'source_uri': current_app.config['CYBERPROTECT_UI_URL'].format(
            observable=output['observable']['value']),
        'reason':
            current_app.config['CTIM_REASON_DEFAULT'].format(
                details['engineId']),
        **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
    }

    return doc


@key_error_handler
def deliberate(observable):
    output = get_cyberprotect_outputs(observable)

    result = Bundle()
    if output:
        scores = output.get('scores', [])
        if len(scores) >= current_app.config['CTR_ENTITIES_LIMIT']:
            scores = scores[:current_app.config['CTR_ENTITIES_LIMIT']]

        for score in scores:
            # need to check because [[]] can be returned in output
            if score and score.get('score') is not None:
                result.add(extract_verdicts(output, score))

    return result


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    g.bundle = Bundle()
    for observable in observables:
        g.bundle.merge(deliberate(observable))

    return jsonify_data(g.bundle.json())


@key_error_handler
def observe(observable):
    output = get_cyberprotect_outputs(observable)

    result = Bundle()
    if output:
        scores = output.get('scores', [])
        if len(scores) >= current_app.config['CTR_ENTITIES_LIMIT']:
            scores = scores[:current_app.config['CTR_ENTITIES_LIMIT']]

        for score in scores:
            # need to check because [[]] can be returned in output
            if score and score.get('score') is not None:
                result.add(extract_verdicts(output, score))

                details = score['details']
                if len(details) >= \
                        current_app.config['CTR_ENTITIES_LIMIT']:
                    details = \
                        details[:current_app.config['CTR_ENTITIES_LIMIT']]

                for detail in details:
                    if detail.get('score') is not None:
                        result.add(extract_judgement(output, detail))
    return result


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    _ = get_jwt()
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    g.bundle = Bundle()
    for observable in observables:
        g.bundle.merge(observe(observable))

    return jsonify_data(g.bundle.json())
