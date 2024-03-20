import random

import pytest
import requests
import requests_mock

from fnc.errors import ErrorType, FncClientError
from tests.api.mocks import MockEndpoint
from tests.utils import *


def test_get_url():
    endpoint = MockEndpoint()
    expected_url = f"{MockEndpoint().version}/{MockEndpoint().endpoint}"

    # Test successful response
    assert endpoint.get_url() == expected_url

    # Test failure cases
    endpoints: list = []

    endpoint = MockEndpoint()
    endpoint.version = None
    endpoints.append(endpoint)

    endpoint = MockEndpoint()
    endpoint.version = ''
    endpoints.append(endpoint)

    endpoint = MockEndpoint()
    endpoint.endpoint = None
    endpoints.append(endpoint)

    endpoint = MockEndpoint()
    endpoint.endpoint = ''
    endpoints.append(endpoint)

    for e in endpoints:
        with pytest.raises(KeyError):
            e.get_url()


def test_evaluate():
    endpoint = MockEndpoint()
    unexpected_arg = get_random_string()

    args: dict = {
        unexpected_arg: get_random_string(),

        'url_arg_1': get_random_string(),
        'url_arg_2': get_random_string(),

        'body_arg_required': get_random_string(),
        'body_arg_multiple': f"{get_random_string()},{get_random_string()}",
        'body_arg_allowed': f"expected_{random.randint(1, 3)}",
        'body_arg_multiple_and_allowed': f"expected_{random.randint(1, 3)},expected_{random.randint(1, 3)}",

        'query_arg_required': get_random_string(),
        'query_arg_multiple': f"{get_random_string()},{get_random_string()}",
        'query_arg_allowed': f"expected_{random.randint(1, 3)}",
        'query_arg_multiple_and_allowed': f"expected_{random.randint(1, 3)},expected_{random.randint(1, 3)}",
    }

    expected_success_result = {
        'url_args': {
            'url_arg_1': args['url_arg_1'],
            'url_arg_2': args['url_arg_2'],
        },
        'body_args': {
            'body_arg_required': args['body_arg_required'],
            'body_arg_multiple': args['body_arg_multiple'].split(','),
            'body_arg_allowed': [args['body_arg_allowed']],
            'body_arg_multiple_and_allowed': args['body_arg_multiple_and_allowed'].split(','),
        },
        'query_args': {
            'query_arg_required': [args['query_arg_required']],
            'query_arg_multiple': args['query_arg_multiple'].split(','),
            'query_arg_allowed': [args['query_arg_allowed']],
            'query_arg_multiple_and_allowed': args['query_arg_multiple_and_allowed'].split(','),
        },
        'control_args': {
            'method': ['METHOD']
        },
        'unexpected_args': {
            unexpected_arg: args[unexpected_arg],
        },
    }

    result = endpoint.evaluate(args=args)
    assert not deep_diff(d1=result, d2=expected_success_result)


def test_validate_successful():
    endpoint = MockEndpoint()

    valid_args: dict = {
        'url_args': {
            'url_arg_1': get_random_string(),
            'url_arg_2': get_random_string(),
        },
        'body_args': {
            'body_arg_required': get_random_string(),
            'body_arg_multiple': f"{get_random_string()},{get_random_string()}",
            'body_arg_allowed': f"expected_{random.randint(1, 3)}",
            'body_arg_multiple_and_allowed': [f"expected_{random.randint(1, 3)}", f"expected_{random.randint(1, 3)}"],
        },
        'query_args': {
            'query_arg_required': get_random_string(),
            'query_arg_multiple': f"{get_random_string()},{get_random_string()}",
            'query_arg_allowed': f"expected_{random.randint(1, 3)}",
            'query_arg_multiple_and_allowed': [f"expected_{random.randint(1, 3)}", f"expected_{random.randint(1, 3)}"],
        },
        'control_args': {
            'method': ['METHOD']
        },
        'unexpected_args': {
        },
    }

    endpoint.validate(valid_args)


def test_validate_failure():
    endpoint = MockEndpoint()

    invalid_args: dict = {
        'url_args': {
            # URL args are always required
            # 'url_arg_1': get_random_string(),
            # 'url_arg_2': get_random_string(),
        },
        'body_args': {
            # 'body_arg_required': get_random_string(),
            'body_arg_multiple': f"{get_random_string()},{get_random_string()}",
            'body_arg_allowed': 'invalid_value',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2', 'invalid_value'],
        },
        'query_args': {
            # 'query_arg_required': get_random_string(),
            'query_arg_multiple': f"{get_random_string()},{get_random_string()}",
            'query_arg_allowed': 'invalid_value',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2', 'invalid_value'],
        },
        'control_args': {
            # Control's arguments do not need validation since they are defined internally in the endpoint
        },
        'unexpected_args': {
            # Any key in this dictionary should be reported as unexpected
            'unexpected_arg': f"{get_random_string()}"
        },
    }
    expected_missing = ['url_arg_1', 'url_arg_2',
                        'query_arg_required', 'body_arg_required']
    expected_invalid = ['body_arg_allowed', 'body_arg_multiple_and_allowed',
                        'query_arg_allowed', 'query_arg_multiple_and_allowed']
    expected_unexpected = ['unexpected_arg']

    with pytest.raises(FncClientError) as e:
        endpoint.validate(invalid_args)

    ex: FncClientError = e.value
    data: dict = ex.error_data

    assert ex.error_type == ErrorType.ENDPOINT_VALIDATION_ERROR
    assert all(arg in expected_missing for arg in data['missing'])
    assert all(arg in expected_invalid for arg in data['invalid'])
    assert all(arg in expected_unexpected for arg in data['unexpected'])


def test_validate_response_successful():
    endpoint = MockEndpoint()

    fake_url = 'http://fake_url.com'
    expected = {
        'response_field_1': get_random_string(),
        'response_field_2': get_random_string(),
    }

    status_code = 200

    with requests_mock.Mocker() as mock_request:
        mock_request.get(fake_url, json=expected, status_code=status_code)
        response = requests.get(fake_url)
        received: dict = endpoint.validate_response(response)
        assert not deep_diff(received, expected)


def test_validate_response_bad_status():
    endpoint = MockEndpoint()

    fake_url = 'http://fake_url.com'
    bad_status_code = random.randrange(400, 599)
    error_json = {
        'error_message': 'error'
    }

    with requests_mock.Mocker() as mock_request:
        mock_request.get(fake_url, json=error_json,
                         status_code=bad_status_code)
        invalid_response = requests.get(fake_url)

        with pytest.raises(FncClientError) as e:
            endpoint.validate_response(invalid_response)

        ex: FncClientError = e.value
        assert ex.error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR


def test_validate_response_bad_json():
    endpoint = MockEndpoint()

    fake_url = 'http://fake_url.com'
    status_code = 200
    bad_content = bytes('invalid', 'utf-8')

    with requests_mock.Mocker() as mock_request:
        mock_request.get(fake_url, content=bad_content,
                         status_code=status_code)
        invalid_response = requests.get(fake_url)

    with pytest.raises(FncClientError) as e:
        endpoint.validate_response(invalid_response)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR


def test_validate_response_bad_status_and_json():
    endpoint = MockEndpoint()

    fake_url = 'http://fake_url.com'
    bad_status_code = random.randrange(400, 599)
    bad_content = bytes('invalid', 'utf-8')

    with requests_mock.Mocker() as mock_request:
        mock_request.get(fake_url, content=bad_content,
                         status_code=bad_status_code)
        invalid_response = requests.get(fake_url)

        with pytest.raises(FncClientError) as e:
            endpoint.validate_response(invalid_response)

        ex: FncClientError = e.value
        assert ex.error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR


def test_validate_invalid_response():
    endpoint = MockEndpoint()

    fake_url = 'http://fake_url.com'
    status_code = 200

    invalid_content = [
        {'response_field_1': get_random_string(), 'extra_field': get_random_string()},
        {'response_field_2': get_random_string(), 'extra_field': get_random_string()},
        {'extra_field': get_random_string()}
    ]

    for content in invalid_content:
        with requests_mock.Mocker() as mock_request:
            mock_request.get(fake_url, json=content, status_code=status_code)
            invalid_response = requests.get(fake_url)

            with pytest.raises(FncClientError) as e:
                endpoint.validate_response(invalid_response)

            ex: FncClientError = e.value
            assert ex.error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR
