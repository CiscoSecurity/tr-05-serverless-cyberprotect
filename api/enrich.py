from datetime import datetime, timedelta
from uuid import uuid4

import requests
from flask import Blueprint, current_app, g

from api.schemas import ObservableSchema
from api.utils import (
    get_json,
    jsonify_data,
    url_for,
    get_response_data,
    format_docs
)

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


def get_cyberprotect_outputs(observable):
    # Return list of responses from Cyberprotect for all observables

    cyberprotect_output = validate_cyberprotect_output(
        observable['value'])

    if cyberprotect_output:
        cyberprotect_output['observable'] = observable

    return cyberprotect_output


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

    judgement_id = f'transient:{uuid4()}'

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


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    g.verdicts = []

    for observable in observables:

        output = get_cyberprotect_outputs(observable)

        if output:
            scores = output['scores']
            if len(scores) >= current_app.config['CTR_ENTITIES_LIMIT']:
                scores = scores[:current_app.config['CTR_ENTITIES_LIMIT']]

            for score in scores:
                # need to check because [[]] can be returned in output
                if score:
                    g.verdicts.append(extract_verdicts(output, score))

    relay_output = {}

    if g.verdicts:
        relay_output['verdicts'] = format_docs(g.verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    g.verdicts = []
    g.judgements = []

    for observable in observables:

        output = get_cyberprotect_outputs(observable)

        if output:

            scores = output['scores']
            if len(scores) >= current_app.config['CTR_ENTITIES_LIMIT']:
                scores = scores[:current_app.config['CTR_ENTITIES_LIMIT']]

            for score in scores:
                # need to check because [[]] can be returned in output
                if score:
                    g.verdicts.append(extract_verdicts(output, score))

                    details = score['details']
                    if len(details) >= \
                            current_app.config['CTR_ENTITIES_LIMIT']:
                        details = \
                            details[:current_app.config['CTR_ENTITIES_LIMIT']]

                    for detail in details:
                        g.judgements.append(extract_judgement(output, detail))

    relay_output = {}

    if g.verdicts:
        relay_output['verdicts'] = format_docs(g.verdicts)
    if g.judgements:
        relay_output['judgements'] = format_docs(g.judgements)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
