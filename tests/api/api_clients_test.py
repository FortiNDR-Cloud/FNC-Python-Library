
import copy
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import pytest
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

from fnc.api.api_client import (
    ApiContext,
    DetectionApi,
    EntityApi,
    FncApiClient,
    SensorApi,
)
from fnc.api.endpoints import EndpointKey
from fnc.errors import ErrorMessages, ErrorType, FncClientError
from fnc.fnc_client import FncClient
from fnc.global_variables import (  # POLLING_MAX_DETECTION_EVENTS,
    CLIENT_DEFAULT_DOMAIN,
    DEFAULT_DATE_FORMAT,
    REQUEST_DEFAULT_TIMEOUT,
    REQUEST_DEFAULT_VERIFY,
    REQUEST_MAXIMUM_RETRY_ATTEMPT,
)
from fnc.utils import datetime_to_utc_str, str_to_utc_datetime
from tests.api.mocks import MockApi, MockEndpoint, MockRestClient
from tests.utils import (  # get_empty_detection_events_response,; get_fetch_dhcp_response,; get_fetch_pdns_response,
    deep_diff,
    get_empty_detections_response,
    get_fake_detection_events_response,
    get_fake_detections_response,
    get_random_endpoint_keys,
    get_random_string,
)


def test_get_api_client_as_singleton(mocker):

    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api_token_1 = 'fake_api_token_1'
    domain_1 = 'fake_domain_1'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)

    same_client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)

    assert client == same_client

    new_client = FncClient.get_api_client(name=agent, api_token=api_token_1, domain=domain, rest_client=None)

    assert client != new_client

    same_client = FncClient.get_api_client(name=agent, api_token=api_token_1, domain=domain, rest_client=None)

    assert new_client == same_client

    new_client_1 = FncClient.get_api_client(name=agent, api_token=api_token_1, domain=domain_1, rest_client=None)

    assert new_client != new_client_1


def test_get_url_failure_missing_url_args(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'

    for _, endpoint in endpoints.items():
        # Assert KeyError is raised if any url argument is missing

        url_args: Dict = {
            'url_arg_1': url_arg_1,
        }
        with pytest.raises(FncClientError) as e:
            client.get_url(e=endpoint, api=api, url_args=url_args)

        ex: FncClientError = e.value
        data: Dict = ex.error_data
        assert isinstance(data['error'], KeyError)


def test_get_url_failure_missing_api_name(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'
    url_arg_2: str = 'fake2'

    for _, endpoint in endpoints.items():
        # Assert KeyError is raised if the api has no name
        url_args: Dict = {
            'url_arg_1': url_arg_1,
            'url_arg_2': url_arg_2,
        }

        mocker.patch('tests.api.mocks.MockApi.get_name', return_value='')
        with pytest.raises(FncClientError) as e:
            client.get_url(e=endpoint, api=api, url_args=url_args)

        ex: FncClientError = e.value
        data: Dict = ex.error_data
        assert ex.error_type == ErrorType.ENDPOINT_VALIDATION_ERROR
        assert isinstance(data['error'], KeyError)


def test_get_url_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    default_domain = CLIENT_DEFAULT_DOMAIN
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client_with_default = FncApiClient(name=agent, api_token=api_token, domain=default_domain, rest_client=None)
    client_with_fake = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'
    url_arg_2: str = 'fake2'

    for _, endpoint in endpoints.items():
        endpoint_url = endpoint.get_url()
        url_args: Dict = {
            'url_arg_1': url_arg_1,
            'url_arg_2': url_arg_2,
        }
        # Assert it succeed if all the arguments are passed

        endpoint_url = endpoint_url.format(**url_args)
        expected_default_url = f'https://{api._api_name}.{default_domain}/{endpoint_url}'
        expected_url = f'https://{api._api_name}.{domain}/{endpoint_url}'
        assert client_with_default.get_url(e=endpoint, api=api,
                                           url_args=url_args) == expected_default_url
        assert client_with_fake.get_url(e=endpoint, api=api,
                                        url_args=url_args) == expected_url


def test_get_endpoint_if_supported_failure_no_endpoint(mocker):

    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)

    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(endpoint=None)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(endpoint='')

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_ERROR


def test_get_endpoint_if_supported_failure_no_support(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    endpoints = list(EndpointKey._member_map_.keys())
    count = len(endpoints)

    unsupported: List = endpoints[slice(0, 1)]
    supported: List = endpoints[slice(1, count)]

    api: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    client.supported_api = [api]

    key_name = unsupported[0].title()
    key: EndpointKey = EndpointKey(key_name)

    # Check it fails if endpoint is supported by several APIs
    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(key)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(key_name)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_ERROR


def test_get_endpoint_if_supported_failure_multiple_support(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)
    api2: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    client.supported_api = [api1, api2]

    key_name = supported[0].title()
    key: EndpointKey = EndpointKey(key_name)

    # Check it fails if endpoint is supported by several APIs
    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(key)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_VALIDATION_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client.get_endpoint_if_supported(key_name)

    ex: FncClientError = e.value
    assert ex.error_type == ErrorType.ENDPOINT_VALIDATION_ERROR


def test_get_endpoint_if_supported_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    supported: List = get_random_endpoint_keys(size=2)
    api1: MockApi = MockApi(endpoints_keys=supported[slice(0, 1)])
    api2: MockApi = MockApi(endpoints_keys=supported[slice(1, 2)])

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
    client.supported_api = [api1, api2]

    for k in supported:
        key_name = k.title()
        key: EndpointKey = EndpointKey(key_name)

        # Check it succeeds if endpoint is supported by single API
        e, a = client.get_endpoint_if_supported(key)
        e1, a1 = client.get_endpoint_if_supported(key_name)

        assert a and a == a1
        assert e and e == e1


def test_retry_mechanism_max_attempt_reached(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    error_types = list(map(lambda c: c, ErrorType))
    error_type = random.choice(error_types)
    fnc_error = FncClientError(
        error_type=error_type,
        error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
        error_data={'error': 'error'}
    )

    max_attempt_reached = REQUEST_MAXIMUM_RETRY_ATTEMPT + random.randint(0, 999)
    assert not client._is_retry_needed(error=fnc_error, attempt=max_attempt_reached)


def test_retry_mechanism_max_attempt_not_reached(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    always_needs_retry = [
        ErrorType.REQUEST_CONNECTION_ERROR,
        ErrorType.REQUEST_TIMEOUT_ERROR,
        ErrorType.GENERIC_ERROR,
    ]
    error_types = list(map(lambda c: c, ErrorType))
    attempt = random.randint(1, REQUEST_MAXIMUM_RETRY_ATTEMPT-1)

    for error_type in error_types:
        fnc_error = FncClientError(
            error_type=error_type,
            error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
            error_data={'error': 'error'}
        )

        if error_type in always_needs_retry:
            assert client._is_retry_needed(error=fnc_error, attempt=attempt)
        elif error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR:
            to_retry = FncClientError(
                error_type=error_type,
                error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
                error_data={'error': 'error', 'status': random.randint(500, 599)}
            )
            assert client._is_retry_needed(error=to_retry, attempt=attempt)

            not_to_retry = FncClientError(
                error_type=error_type,
                error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
                error_data={'error': 'error', 'status': random.randint(400, 499)}
            )
            assert not client._is_retry_needed(error=not_to_retry, attempt=attempt)
        else:
            assert not client._is_retry_needed(error=fnc_error, attempt=attempt)


def test_retry_mechanism_map_error(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)
    spy_map_error = mocker.spy(client, '_map_error')

    error_types = list(map(lambda c: c, ErrorType))
    error_type = random.choice(error_types)
    attempt = random.randint(1, REQUEST_MAXIMUM_RETRY_ATTEMPT+10)

    fnc_error = FncClientError(
        error_type=error_type,
        error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
        error_data={'error': 'error'}
    )

    _ = client._is_retry_needed(error=fnc_error, attempt=attempt)
    assert spy_map_error.call_count == 0

    _ = client._is_retry_needed(error=Exception(), attempt=attempt)
    assert spy_map_error.call_count == 1


def test_map_error(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    error_types = list(map(lambda c: c, ErrorType))
    error_type = random.choice(error_types)

    fnc_error = FncClientError(
        error_type=error_type,
        error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
        error_data={'error': 'error'}
    )
    connection_error = ConnectionError()
    timeout_error = Timeout()
    http_error = HTTPError()
    request_error = RequestException()
    other_error = Exception()

    assert client._map_error(fnc_error) == fnc_error

    errors = [connection_error, timeout_error, http_error, request_error, other_error]
    mapped_errors = []

    mapped_error = client._map_error(connection_error)
    mapped_errors.append(mapped_error)
    assert mapped_error.error_type == ErrorType.REQUEST_CONNECTION_ERROR

    mapped_error = client._map_error(timeout_error)
    mapped_errors.append(mapped_error)
    assert mapped_error.error_type == ErrorType.REQUEST_TIMEOUT_ERROR

    mapped_error = client._map_error(http_error)
    mapped_errors.append(mapped_error)
    assert mapped_error.error_type == ErrorType.REQUEST_HTTP_ERROR

    mapped_error = client._map_error(request_error)
    mapped_errors.append(mapped_error)
    assert mapped_error.error_type == ErrorType.REQUEST_ERROR

    mapped_error = client._map_error(other_error)
    mapped_errors.append(mapped_error)
    assert mapped_error.error_type == ErrorType.GENERIC_ERROR

    assert all(isinstance(e, FncClientError) for e in mapped_errors)
    assert all('error' in mapped_errors[i].error_data and mapped_errors[i].error_data.get('error') == errors[i] for i in range(len(errors)))


def test_call_endpoint_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    spy_send_request = mocker.spy(rest_client, 'send_request')
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')
    spy_endpoint_validate_response = mocker.spy(endpoint, 'validate_response')

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    req_args = {
        'method': 'METHOD',
        'verify': REQUEST_DEFAULT_VERIFY,
        'timeout': REQUEST_DEFAULT_TIMEOUT,
        'headers': {
            'Authorization': 'IBToken fake_api_token',
            'User-Agent': 'FNC_Py_Client-v1.0.0-fake_agent',
            'Content-Type': 'application/json'
        },
        'url': 'https://mock_api.fake_domain/expected_version/expected_endpoint/url_arg_1_value/url_arg_2_value',
        'params': {
            'query_arg_required': rand_string,
            'query_arg_multiple': [rand_string, rand_string],
            'query_arg_allowed': 'expected_1',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        },
        'json': {
            'body_arg_required': rand_string,
            'body_arg_multiple': [rand_string, rand_string],
            'body_arg_allowed': 'expected_1',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        }
    }

    # Testing with Default Control Arguments

    client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == 1
    assert spy_validate_request.call_count == 1
    assert deep_diff(rest_client.validate_request_args, req_args)
    assert not spy_validate_request.spy_exception
    assert spy_send_request.call_count == 1
    assert spy_endpoint_validate_response.call_count == 1
    assert deep_diff(rest_client.send_request_args, req_args)
    assert not spy_send_request.spy_exception

    # Testing with updated Default Control Arguments

    r_timeout = random.randint(0, 100)
    r_verify = random.randint(0, 1) == 1
    r_proxies = {'https': get_random_string()}

    client.set_default_control_args(
        {
            'proxies': r_proxies,
            'verify': r_verify,
            'timeout': r_timeout
        }
    )
    req_args.update({'verify': r_verify})
    req_args.update({'timeout': r_timeout})
    req_args.update({'proxies': r_proxies})

    client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == 2
    assert spy_validate_request.call_count == 2
    assert deep_diff(rest_client.validate_request_args, req_args)
    assert not spy_validate_request.spy_exception
    assert spy_send_request.call_count == 2
    assert spy_endpoint_validate_response.call_count == 2
    assert deep_diff(rest_client.send_request_args, req_args)
    assert not spy_send_request.spy_exception


def test_call_endpoint_failure_invalid_endpoint(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)

    endpoint_validation_error = FncClientError(
        error_type=ErrorType.ENDPOINT_VALIDATION_ERROR,
        error_message=ErrorMessages.ENDPOINT_ARGUMENT_VALIDATION,
        error_data={'endpoint': endpoint_key.name, 'missing': 'missing', 'unexpected': 'unexpected', 'invalid': 'invalid'}
    )

    mock_endpoint_validate = mocker.patch(
        'fnc.api.endpoints.Endpoint.validate', side_effect=endpoint_validation_error)

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    # Testing passing EndpointKey
    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key, args=args)

    assert mock_endpoint_validate.call_count == 1
    assert e.value == endpoint_validation_error

    # Testing passing endpoint as str
    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key.name, args=args)

    assert mock_endpoint_validate.call_count == 2
    assert e.value == endpoint_validation_error


def test_call_endpoint_failure_invalid_request(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()

    request_validation_error = FncClientError(
        error_type=ErrorType.REQUEST_VALIDATION_ERROR,
        error_message=ErrorMessages.REQUEST_URL_NOT_PROVIDED
    )

    mock_validate_request = mocker.patch.object(
        rest_client, 'validate_request', side_effect=request_validation_error)

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    req_args = {
        'method': 'METHOD',
        'verify': REQUEST_DEFAULT_VERIFY,
        'timeout': REQUEST_DEFAULT_TIMEOUT,
        'headers': {
            'Authorization': 'IBToken fake_api_token',
            'User-Agent': 'FNC_Py_Client-v1.0.0-fake_agent',
            'Content-Type': 'application/json'
        },
        'url': 'https://mock_api.fake_domain/expected_version/expected_endpoint/url_arg_1_value/url_arg_2_value',
        'params': {
            'query_arg_required': rand_string,
            'query_arg_multiple': [rand_string, rand_string],
            'query_arg_allowed': 'expected_1',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        },
        'json': {
            'body_arg_required': rand_string,
            'body_arg_multiple': [rand_string, rand_string],
            'body_arg_allowed': 'expected_1',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        }
    }

    # Testing with Default Control Arguments

    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == 1
    assert mock_validate_request.call_count == 1
    assert e.value == request_validation_error
    assert deep_diff(rest_client.validate_request_args, req_args)


def test_call_endpoint_failure_failed_request(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()

    send_request_error = FncClientError(
        error_type=ErrorType.REQUEST_CONNECTION_ERROR,
        error_message=ErrorMessages.REQUEST_CONNECTION_ERROR
    )
    mock_send_request = mocker.patch.object(
        rest_client, 'send_request', side_effect=send_request_error)
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    need_retry_attempts = random.randint(1, REQUEST_MAXIMUM_RETRY_ATTEMPT)
    need_retry = [True for i in range(need_retry_attempts)]
    need_retry[need_retry_attempts-1] = False

    mock_need_retry = mocker.patch.object(client, "_is_retry_needed", side_effect=need_retry)

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')
    spy_endpoint_validate_response = mocker.spy(endpoint, 'validate_response')

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    req_args = {
        'method': 'METHOD',
        'verify': REQUEST_DEFAULT_VERIFY,
        'timeout': REQUEST_DEFAULT_TIMEOUT,
        'headers': {
            'Authorization': 'IBToken fake_api_token',
            'User-Agent': 'FNC_Py_Client-v1.0.0-fake_agent',
            'Content-Type': 'application/json'
        },
        'url': 'https://mock_api.fake_domain/expected_version/expected_endpoint/url_arg_1_value/url_arg_2_value',
        'params': {
            'query_arg_required': rand_string,
            'query_arg_multiple': [rand_string, rand_string],
            'query_arg_allowed': 'expected_1',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        },
        'json': {
            'body_arg_required': rand_string,
            'body_arg_multiple': [rand_string, rand_string],
            'body_arg_allowed': 'expected_1',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        }
    }

    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == need_retry_attempts
    assert spy_validate_request.call_count == need_retry_attempts
    assert deep_diff(rest_client.validate_request_args, req_args)
    assert mock_need_retry.call_count == need_retry_attempts
    assert mock_send_request.call_count == need_retry_attempts
    assert e.value == send_request_error
    assert spy_endpoint_validate_response.call_count == 0


def test_call_endpoint_failure_invalid_response(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    spy_send_request = mocker.spy(rest_client, 'send_request')
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    need_retry_attempts = random.randint(1, REQUEST_MAXIMUM_RETRY_ATTEMPT)
    need_retry = [True for i in range(need_retry_attempts)]
    need_retry[need_retry_attempts-1] = False

    mock_need_retry = mocker.patch.object(client, "_is_retry_needed", side_effect=need_retry)

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    endpoint_response_validation_error = FncClientError(
        error_type=ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR,
        error_message=ErrorMessages.ENDPOINT_RESPONSE_INVALID,
        error_data={'endpoint': endpoint_key.name, 'error': 'error'}
    )

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')
    mock_endpoint_validate_response = mocker.patch.object(
        endpoint, 'validate_response', side_effect=endpoint_response_validation_error)

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    req_args = {
        'method': 'METHOD',
        'verify': REQUEST_DEFAULT_VERIFY,
        'timeout': REQUEST_DEFAULT_TIMEOUT,
        'headers': {
            'Authorization': 'IBToken fake_api_token',
            'User-Agent': 'FNC_Py_Client-v1.0.0-fake_agent',
            'Content-Type': 'application/json'
        },
        'url': 'https://mock_api.fake_domain/expected_version/expected_endpoint/url_arg_1_value/url_arg_2_value',
        'params': {
            'query_arg_required': rand_string,
            'query_arg_multiple': [rand_string, rand_string],
            'query_arg_allowed': 'expected_1',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        },
        'json': {
            'body_arg_required': rand_string,
            'body_arg_multiple': [rand_string, rand_string],
            'body_arg_allowed': 'expected_1',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        }
    }

    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == need_retry_attempts
    assert spy_validate_request.call_count == need_retry_attempts
    assert deep_diff(rest_client.validate_request_args, req_args)
    assert mock_need_retry.call_count == need_retry_attempts
    assert spy_send_request.call_count == need_retry_attempts
    assert deep_diff(rest_client.send_request_args, req_args)
    assert e.value == endpoint_response_validation_error
    assert mock_endpoint_validate_response.call_count == need_retry_attempts


def test_call_endpoint_failure_retry_stop_when_false(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    spy_send_request = mocker.spy(rest_client, 'send_request')
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    supported: List = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    need_retry_attempts = REQUEST_MAXIMUM_RETRY_ATTEMPT + 1
    need_retry = [True for i in range(need_retry_attempts)]
    need_retry[need_retry_attempts-1] = False
    mock_need_retry = mocker.patch.object(client, "_is_retry_needed", side_effect=need_retry)

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    endpoint_response_validation_error = FncClientError(
        error_type=ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR,
        error_message=ErrorMessages.ENDPOINT_RESPONSE_INVALID,
        error_data={'endpoint': endpoint_key.name, 'error': 'error'}
    )

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')
    mock_endpoint_validate_response = mocker.patch.object(
        endpoint, 'validate_response', side_effect=endpoint_response_validation_error)

    rand_string = get_random_string(),
    args: Dict = {
        'url_arg_1': 'url_arg_1_value',
        'url_arg_2': 'url_arg_2_value',

        'body_arg_required': rand_string,
        'body_arg_multiple': f"{rand_string},{rand_string}",
        'body_arg_allowed': "expected_1",
        'body_arg_multiple_and_allowed': "expected_1,expected_2",

        'query_arg_required': rand_string,
        'query_arg_multiple': f"{rand_string},{rand_string}",
        'query_arg_allowed': "expected_1",
        'query_arg_multiple_and_allowed': "expected_1,expected_2",
    }
    req_args = {
        'method': 'METHOD',
        'verify': REQUEST_DEFAULT_VERIFY,
        'timeout': REQUEST_DEFAULT_TIMEOUT,
        'headers': {
            'Authorization': 'IBToken fake_api_token',
            'User-Agent': 'FNC_Py_Client-v1.0.0-fake_agent',
            'Content-Type': 'application/json'
        },
        'url': 'https://mock_api.fake_domain/expected_version/expected_endpoint/url_arg_1_value/url_arg_2_value',
        'params': {
            'query_arg_required': rand_string,
            'query_arg_multiple': [rand_string, rand_string],
            'query_arg_allowed': 'expected_1',
            'query_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        },
        'json': {
            'body_arg_required': rand_string,
            'body_arg_multiple': [rand_string, rand_string],
            'body_arg_allowed': 'expected_1',
            'body_arg_multiple_and_allowed': ['expected_1', 'expected_2']
        }
    }

    with pytest.raises(FncClientError) as e:
        client.call_endpoint(endpoint=endpoint_key, args=args)

    assert spy_endpoint_validate.call_count == need_retry_attempts
    assert spy_validate_request.call_count == need_retry_attempts
    assert deep_diff(rest_client.validate_request_args, req_args)
    assert mock_need_retry.call_count == need_retry_attempts
    assert spy_send_request.call_count == need_retry_attempts
    assert deep_diff(rest_client.send_request_args, req_args)
    assert e.value == endpoint_response_validation_error
    assert mock_endpoint_validate_response.call_count == need_retry_attempts


def test_validate_continuous_polling_args_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    sort_by = 'device_ip'
    muted = random.choice(['true', 'false', ''])
    muted_rule = random.choice(['true', 'false', ''])
    muted_devices = random.choice(['true', 'false', ''])
    status = random.choice(['active', 'resolved', ''])

    now = datetime.now(timezone.utc)
    created_or_shared_start_date = datetime_to_utc_str(now - timedelta(days=random.randint(1, 100)), DEFAULT_DATE_FORMAT)
    created_or_shared_end_date = datetime_to_utc_str(now, DEFAULT_DATE_FORMAT)

    valid_args = {
        'sort_by': sort_by,
        'muted': muted,
        'muted_rule': muted_rule,
        'muted_devices': muted_devices,
        'status': status,
        'created_or_shared_start_date': created_or_shared_start_date,
        'created_or_shared_end_date': created_or_shared_end_date,
    }

    client._validate_continuous_polling_args(valid_args)


def test_and_validate_get_search_window_succeed(mocker):
    # TODO Needs to be checked. It seems to be failing randomly
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    now = datetime.now(timezone.utc)

    # default_delay = 10
    delay = random.randint(11, 50)

    # default_date = now - timedelta(minutes=default_delay)
    # default_date_with_delay = now - timedelta(minutes=delay)

    # default_start_date = now.replace(hour=0, minute=0, second=0,
    #                                  microsecond=0, tzinfo=timezone.utc)

    start_date = now - timedelta(minutes=random.randint(delay+1, 100))
    start_date_str = datetime_to_utc_str(start_date)
    # default_start_date = default_date

    checkpoint = now - timedelta(minutes=random.randint(delay+1, 100))
    checkpoint_str = datetime_to_utc_str(checkpoint)

    end_date = now - timedelta(minutes=delay)
    # default_end_date = default_date

    received_start_date, received_end_date = client._get_and_validate_search_window(
        start_date_str=start_date_str, polling_delay=delay, checkpoint=checkpoint_str)

    assert received_start_date == checkpoint
    assert received_end_date - end_date < timedelta(seconds=1)

    received_start_date, received_end_date = client._get_and_validate_search_window(
        start_date_str=start_date_str, polling_delay=delay)

    assert received_start_date == start_date
    assert received_end_date - end_date < timedelta(seconds=1)

    r_d = random.randint(1, 7)
    r_h = random.randint(1, 24)
    r_m = random.randint(1, 60)
    r_s = random.randint(1, 60)

    random_start_date = now - timedelta(days=r_d, hours=r_h, minutes=r_m, seconds=r_s)

    r_d = random.randint(0, r_d-1)
    r_h = random.randint(0, r_h-1)
    r_m = random.randint(0, r_m-1)
    r_s = random.randint(0, r_s-1)

    random_end_date = now - timedelta(days=r_d, hours=r_h, minutes=r_m, seconds=r_s)

    start_date_str = datetime_to_utc_str(random_start_date)
    end_date_str = datetime_to_utc_str(random_end_date)

    received_start_date, received_end_date = client._get_and_validate_search_window(start_date_str=start_date_str, end_date_str=end_date_str)

    assert received_start_date == random_start_date
    assert received_end_date == random_end_date


def test_and_validate_get_search_window_failure_inverted(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    now = datetime.now(timezone.utc)

    delay = random.randint(11, 100)
    past_1 = random.randint(2, 24)
    past_2 = random.randint(1, past_1-1)

    inverted_start_date = datetime_to_utc_str(now - timedelta(hours=past_2))
    inverted_end_date = datetime_to_utc_str(now - timedelta(hours=past_1))

    close_start_date = now - timedelta(minutes=random.randint(1, delay-1))
    close_start_date_str = datetime_to_utc_str(close_start_date)

    close_end_date = now - timedelta(minutes=random.randint(1, delay-1))
    close_end_date_str = datetime_to_utc_str(close_end_date)

    future_start_date = now + timedelta(minutes=random.randint(1, 100))
    future_start_date_str = datetime_to_utc_str(future_start_date)

    future_end_date = now + timedelta(minutes=random.randint(1, 100))
    future_end_date_str = datetime_to_utc_str(future_end_date)

    # If start and end date are inverted an Inverted Time Window exception is thrown

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=inverted_start_date, end_date_str=inverted_end_date, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_INVERTED_TIME_WINDOW_ERROR

    # If no start date is passed, start_date and end_date becomes equals and
    # Empty Time Window exception is thrown

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window()

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    # If start and end date are in the future the default is used and an Empty Time Window exception is thrown

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=close_start_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=future_start_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            end_date_str=close_end_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            end_date_str=future_end_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=close_start_date_str, end_date_str=close_end_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=future_start_date_str, end_date_str=future_end_date_str, polling_delay=delay)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR


def test_and_validate_get_search_window_failure_invalid_start_date(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    start_date_str = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        _, _ = client._get_and_validate_search_window(
            start_date_str=start_date_str)

    assert e.value.error_type == ErrorType.POLLING_TIME_WINDOW_ERROR


def test_validate_continuous_polling_args_failure_wrong_status(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    sort_by = 'device_ip'
    muted = random.choice(['true', 'false', ''])
    muted_rule = random.choice(['true', 'false', ''])
    muted_devices = random.choice(['true', 'false', ''])
    status = random.choice(['active', 'resolved', ''])

    now = datetime.now(timezone.utc)
    created_or_shared_start_date = datetime_to_utc_str(now - timedelta(days=random.randint(1, 100)), DEFAULT_DATE_FORMAT)
    created_or_shared_end_date = datetime_to_utc_str(now, DEFAULT_DATE_FORMAT)

    valid_args = {
        'sort_by': sort_by,
        'muted': muted,
        'muted_rule': muted_rule,
        'muted_devices': muted_devices,
        'status': status,
        'created_or_shared_start_date': created_or_shared_start_date,
        'created_or_shared_end_date': created_or_shared_end_date,
    }

    client._validate_continuous_polling_args(valid_args)

    invalid_args = valid_args.copy()
    invalid_args['status'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR


def test_validate_continuous_polling_args_failure_wrong_muted_values(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    sort_by = 'device_ip'
    muted = random.choice(['true', 'false', ''])
    muted_rule = random.choice(['true', 'false', ''])
    muted_device = random.choice(['true', 'false', ''])
    status = random.choice(['active', 'resolved', ''])

    now = datetime.now(timezone.utc)
    created_or_shared_start_date = datetime_to_utc_str(now - timedelta(days=random.randint(1, 100)), DEFAULT_DATE_FORMAT)
    created_or_shared_end_date = datetime_to_utc_str(now, DEFAULT_DATE_FORMAT)

    valid_args = {
        'sort_by': sort_by,
        'muted': muted,
        'muted_rule': muted_rule,
        'muted_device': muted_device,
        'status': status,
        'created_or_shared_start_date': created_or_shared_start_date,
        'created_or_shared_end_date': created_or_shared_end_date,
    }

    client._validate_continuous_polling_args(valid_args)

    invalid_args = valid_args.copy()
    invalid_args['muted'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR

    invalid_args = valid_args.copy()
    invalid_args['muted_rule'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR

    invalid_args = valid_args.copy()
    invalid_args['muted_device'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR


def test_validate_continuous_polling_args_failure_wrong_sort_by(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    sort_by = 'device_ip'
    muted = random.choice(['true', 'false', ''])
    muted_rule = random.choice(['true', 'false', ''])
    muted_devices = random.choice(['true', 'false', ''])
    status = random.choice(['active', 'resolved', ''])

    now = datetime.now(timezone.utc)
    created_or_shared_start_date = datetime_to_utc_str(now - timedelta(days=random.randint(1, 100)), DEFAULT_DATE_FORMAT)
    created_or_shared_end_date = datetime_to_utc_str(now, DEFAULT_DATE_FORMAT)

    valid_args = {
        'sort_by': sort_by,
        'muted': muted,
        'muted_rule': muted_rule,
        'muted_devices': muted_devices,
        'status': status,
        'created_or_shared_start_date': created_or_shared_start_date,
        'created_or_shared_end_date': created_or_shared_end_date,
    }

    client._validate_continuous_polling_args(valid_args)

    invalid_args = valid_args.copy()
    invalid_args['sort_by'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR

    invalid_args = valid_args.copy()
    invalid_args.pop('sort_by')

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR


def test_validate_continuous_polling_args_failure_missing_date(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    sort_by = 'device_ip'
    muted = random.choice(['true', 'false', ''])
    muted_rule = random.choice(['true', 'false', ''])
    muted_devices = random.choice(['true', 'false', ''])
    status = random.choice(['active', 'resolved', ''])

    now = datetime.now(timezone.utc)
    created_or_shared_start_date = datetime_to_utc_str(now - timedelta(days=random.randint(1, 100)), DEFAULT_DATE_FORMAT)
    created_or_shared_end_date = datetime_to_utc_str(now, DEFAULT_DATE_FORMAT)

    valid_args = {
        'sort_by': sort_by,
        'muted': muted,
        'muted_rule': muted_rule,
        'muted_devices': muted_devices,
        'status': status,
        'created_or_shared_start_date': created_or_shared_start_date,
        'created_or_shared_end_date': created_or_shared_end_date,
    }

    client._validate_continuous_polling_args(valid_args)

    invalid_args = valid_args.copy()
    invalid_args['status'] = get_random_string(10)

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR

    invalid_args = valid_args.copy()
    invalid_args.pop('created_or_shared_start_date')

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR

    invalid_args = valid_args.copy()
    invalid_args.pop('created_or_shared_end_date')

    with pytest.raises(FncClientError) as e:
        client._validate_continuous_polling_args(invalid_args)

    assert e.value.error_type == ErrorType.POLLING_VALIDATION_ERROR


def test_prepare_continuous_polling_valid_args_from_context(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    arg_key = get_random_string(10)
    arg_value = get_random_string(10)
    offset = random.randint(1, 10000)

    args_without_offset = {
        arg_key: arg_value
    }

    args_with_offset = {
        arg_key: arg_value,
        'offset': offset
    }
    context = ApiContext()

    mock_validate_args = mocker.patch.object(client, '_validate_continuous_polling_args')
    context.update_polling_args(args=args_without_offset)
    received = client._prepare_continuous_polling(context=context)

    assert mock_validate_args.call_count == 1
    assert len(received) == 2
    assert received.get(arg_key, None) == arg_value
    assert received.get('offset', None) == 0

    mock_validate_args = mocker.patch.object(client, '_validate_continuous_polling_args')
    context.update_polling_args(args=args_with_offset)
    received = client._prepare_continuous_polling(context=context)

    assert mock_validate_args.call_count == 1
    assert len(received) == 2
    assert received.get(arg_key, None) == arg_value
    assert received.get('offset', None) == offset


def test_prepare_continuous_polling_invalid_args_from_context(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    arg_key = get_random_string(10)
    arg_value = get_random_string(10)

    args_without_offset = {
        arg_key: arg_value
    }

    context = ApiContext()

    fnc_error = FncClientError(
        error_type=ErrorType.GENERIC_ERROR,
        error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
        error_data={'error': 'error'}
    )
    mock_validate_args = mocker.patch.object(client, '_validate_continuous_polling_args', side_effect=[fnc_error, None])

    # If no start date is passed the get_and_validate_search_window should fail
    # with Empty Time Window since start_date and end_date becomes equal
    with pytest.raises(FncClientError) as e:
        _ = client._prepare_continuous_polling(context=context)

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    now = datetime.now(tz=timezone.utc)
    start_date = now - timedelta(minutes=random.randint(11, 100))
    start_date_str = datetime_to_utc_str(start_date, DEFAULT_DATE_FORMAT)

    context.update_polling_args(args=args_without_offset)
    received = client._prepare_continuous_polling(context=context, args={'start_date': start_date_str})

    default_args = client.get_default_polling_args()

    assert mock_validate_args.call_count == 2
    assert all(k in received and str(received.get(k)).lower() == str(default_args.get(k)).lower() for k in default_args)
    assert 'created_or_shared_start_date' in received
    assert 'created_or_shared_end_date' in received


def test_prepare_continuous_polling_without_args(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # If no start date is passed the get_and_validate_search_window should fail
    # with Invalid Time Window since start_date and end_date becomes equal
    with pytest.raises(FncClientError) as e:
        _ = client._prepare_continuous_polling()

    assert e.value.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR

    now = datetime.now(tz=timezone.utc)
    start_date = now - timedelta(minutes=random.randint(11, 100))
    start_date_str = datetime_to_utc_str(start_date, DEFAULT_DATE_FORMAT)

    received = client._prepare_continuous_polling(args={'start_date': start_date_str})

    default_args = client.get_default_polling_args()

    assert all(k in received and str(received.get(k)).lower() == str(default_args.get(k)).lower() for k in default_args)
    assert 'created_or_shared_start_date' in received
    assert 'created_or_shared_end_date' in received


def test_prepare_continuous_polling_validate_args_before_return_them(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': True,
        'include_signature': True,
        'include_events': True,
        'start_date': '1 hour'
    }

    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    mock_validate_args = mocker.patch.object(client, '_validate_continuous_polling_args')
    received_args = client._prepare_continuous_polling(args=polling_args)

    assert mock_validate_args.call_count == 1

    for c in mock_validate_args.call_args_list:
        assert deep_diff(received_args, c.kwargs)
        # assert all(k in received_args and received_args.get(k) == expected_args[i].get(k) for k in c.kwargs)


@pytest.mark.skip('This test is in development')
def test_continuous_polling_failure(mocker):
    assert False


def test_continuous_polling_including_nothing(mocker):
    now = datetime.now(tz=timezone.utc)
    start_date = now - timedelta(minutes=15)
    start_date_str = datetime_to_utc_str(start_date, DEFAULT_DATE_FORMAT)

    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': False,
        'include_signature': False,
        'include_events': False,
        'start_date': start_date_str
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    detections_response = get_fake_detections_response(domain=domain, d_count=1, r_count=1)
    fake_rule = detections_response['rules'][0]

    mock_call_endpoint = mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[
                                      copy.deepcopy(detections_response), copy.deepcopy(get_empty_detections_response())])

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    assert mock_validate_token.call_count == 1

    client.supported_api = [DetectionApi, SensorApi, EntityApi]
    client.get_logger().set_level(level=logging.DEBUG)
    call = 0
    for response in client.continuous_polling(args=polling_args):
        call += 1
        if call == 1:
            assert len(response['detections']) == 1
            detection = response['detections'][0]
            assert 'rule_uuid' in detection and detection.get('rule_uuid') == fake_rule['uuid']
            assert 'rule_name' in detection and detection.get('rule_name') == fake_rule['name']
            assert 'rule_severity' in detection and detection.get('rule_severity') == fake_rule['severity']
            assert 'rule_confidence' in detection and detection.get('rule_confidence') == fake_rule['confidence']
            assert 'rule_category' in detection and detection.get('rule_category') == fake_rule['category']
            assert 'rule_primary_attack_id' in detection and detection.get('rule_primary_attack_id') == fake_rule['primary_attack_id']
            assert 'rule_secondary_attack_id' in detection and detection.get('rule_secondary_attack_id') == fake_rule['secondary_attack_id']
            assert 'rule_url' in detection and detection.get('rule_url') == fake_rule['rule_url']
            assert 'rule_description' not in detection
            assert 'rule_signature' not in detection

            assert 'events' not in response or not response.get('events')
        elif call == 2:
            assert len(response['detections']) == 0
        else:
            # Detections can only be returned twice in this test. The first time with one detection and the second one with none.
            assert False

    assert mock_call_endpoint.call_count == 2

    i = 0
    expected_endpoints = [EndpointKey.GET_DETECTIONS, EndpointKey.GET_DETECTIONS]
    expected_args = [
        {'offset': 0, 'status': polling_args.get('status'), 'sort_by': 'device_ip', 'sort_order': 'asc',
         'include': 'rules, indicators', 'created_or_shared_start_date': start_date_str},
        {'offset': 1, 'status': polling_args.get(
            'status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'}
    ]
    for c in mock_call_endpoint.call_args_list:
        assert c.kwargs
        assert expected_endpoints[i] == c.kwargs.get('endpoint', None)
        received_args = c.kwargs.get('args', {})
        assert all(k in received_args and received_args.get(k) == expected_args[i].get(k) for k in expected_args[i])
        i += 1


def test_continuous_polling_including_all(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': True,
        'include_signature': True,
        'include_events': True,
        'start_date': '1 hour'
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    detections_response = get_fake_detections_response(domain=domain, d_count=1, r_count=1)
    fake_rule = detections_response['rules'][0]
    fake_detection = detections_response['detections'][0]
    detections_event_response = get_fake_detection_events_response(count=1, detections=detections_response['detections'])
    fake_detection_events = detections_event_response['events']

    mock_call_endpoint = mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[
                                      copy.deepcopy(detections_response),
                                      copy.deepcopy(detections_event_response),
                                      copy.deepcopy(get_empty_detections_response())])

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    assert mock_validate_token.call_count == 1

    client.supported_api = [DetectionApi, SensorApi, EntityApi]

    call = 0
    for response in client.continuous_polling(args=polling_args):
        call += 1
        if call == 1:
            assert len(response['detections']) == 1
            detection = response['detections'][0]
            assert 'rule_uuid' in detection and detection.get('rule_uuid') == fake_rule['uuid']
            assert 'rule_name' in detection and detection.get('rule_name') == fake_rule['name']
            assert 'rule_severity' in detection and detection.get('rule_severity') == fake_rule['severity']
            assert 'rule_confidence' in detection and detection.get('rule_confidence') == fake_rule['confidence']
            assert 'rule_category' in detection and detection.get('rule_category') == fake_rule['category']
            assert 'rule_description' in detection and detection.get('rule_description') == fake_rule['description']
            assert 'rule_signature' in detection and detection.get('rule_signature') == fake_rule['query_signature']
            assert 'rule_primary_attack_id' in detection and detection.get('rule_primary_attack_id') == fake_rule['primary_attack_id']
            assert 'rule_secondary_attack_id' in detection and detection.get('rule_secondary_attack_id') == fake_rule['secondary_attack_id']
            assert 'rule_url' in detection and detection.get('rule_url') == fake_rule['rule_url']

            assert 'events' in response
            assert detection.get('uuid') in response.get('events')
            assert len(response.get('events').get(detection.get('uuid'))) == 1
            received_event = response.get('events').get(detection.get('uuid'))[0]
            assert deep_diff(received_event, fake_detection_events)
        elif call == 2:
            assert len(response['detections']) == 0
        else:
            # Detections can only be returned twice in this test. The first time with one detection and the second one with none.
            assert False

    assert mock_call_endpoint.call_count == 3

    i = 0
    expected_endpoints = [EndpointKey.GET_DETECTIONS, EndpointKey.GET_DETECTION_EVENTS, EndpointKey.GET_DETECTIONS]
    expected_args = [
        {'offset': 0, 'status': polling_args.get('status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'},
        {'detection_uuid': fake_detection['uuid'], 'offset': 0},
        {'offset': 1, 'status': polling_args.get(
            'status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'}
    ]
    for c in mock_call_endpoint.call_args_list:
        assert c.kwargs
        assert expected_endpoints[i] == c.kwargs.get('endpoint', None)
        received_args = c.kwargs.get('args')
        assert all(k in received_args and received_args.get(k) == expected_args[i].get(k) for k in expected_args[i])
        i += 1


def test_continuous_polling_failure_get_detections_fails(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': True,
        'include_signature': True,
        'include_events': True,
        'start_date': '1 hour'
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    unexpected_error = Exception()

    empty_window_error = FncClientError(
        error_type=ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR,
        error_message=ErrorMessages.POLLING_EMPTY_TIME_WINDOW_ERROR
    )

    known_error = FncClientError(
        ErrorType.REQUEST_CONNECTION_ERROR,
        ErrorMessages.REQUEST_CONNECTION_ERROR,
        {'url': 'masked_url', 'error': 'error'}
    )

    rest_client = MockRestClient()

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    assert mock_validate_token.call_count == 1

    client.supported_api = [DetectionApi, SensorApi, EntityApi]

    # If the error thrown is Polling Empty Window return empty response
    mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[empty_window_error])
    for response in client.continuous_polling(args=polling_args):
        assert response == {}

    # If the error thrown is not Polling Empty Window raise it again
    mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[known_error])
    with pytest.raises(FncClientError) as e:
        for response in client.continuous_polling(args=polling_args):
            assert not response
    assert e.value == known_error

    # If the error thrown is not Polling Empty Window raise it again
    mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[unexpected_error])
    with pytest.raises(FncClientError) as e:
        for response in client.continuous_polling(args=polling_args):
            assert not response
    assert e.value != known_error
    assert e.value.error_type == ErrorType.GENERIC_ERROR
    assert e.value.exception == unexpected_error


def test_get_splitted_context_past_start_and_end_dates(mocker):
    random_days_past_1 = random.randint(2, 100)
    random_days_past_2 = random.randint(1, random_days_past_1)

    now = datetime.now(tz=timezone.utc)
    date_past_1 = now - timedelta(days=random_days_past_1)
    date_past_1_str = datetime_to_utc_str(date_past_1, DEFAULT_DATE_FORMAT)
    date_past_2 = now - timedelta(days=random_days_past_2)
    date_past_2_str = datetime_to_utc_str(date_past_2, DEFAULT_DATE_FORMAT)

    random_delay = random.randint(1, 60)
    expected_checkpoint = now - timedelta(minutes=random_delay)

    polling_args = {
        'polling_delay': random_delay,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': random.choice([True, False, 'All']),
        'pull_muted_rules':  random.choice([True, False, 'All']),
        'pull_muted_devices':  random.choice([True, False, 'All']),
        'include_description': random.choice([True, False]),
        'include_signature': random.choice([True, False]),
        'include_events': random.choice([True, False]),
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # Test both start and end dates in the past
    polling_args['start_date'] = date_past_1_str
    polling_args['end_date'] = date_past_2_str

    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert history['start_date'] == date_past_1_str
    assert history['end_date'] == date_past_2_str
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint - expected_checkpoint < timedelta(seconds=1)

    assert not context.get_history()


def test_get_splitted_context_past_start_date_future_end_date(mocker):
    random_days_past_1 = random.randint(2, 100)
    random_days_future_1 = random.randint(1, 99)

    now = datetime.now(tz=timezone.utc)
    date_past_1 = now - timedelta(days=random_days_past_1)
    date_past_1_str = datetime_to_utc_str(date_past_1, DEFAULT_DATE_FORMAT)
    date_future_1 = now + timedelta(days=random_days_future_1)
    date_future_1_str = datetime_to_utc_str(date_future_1, DEFAULT_DATE_FORMAT)

    random_delay = random.randint(1, 60)
    expected_checkpoint = now - timedelta(minutes=random_delay)

    polling_args = {
        'polling_delay': random_delay,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': random.choice([True, False, 'All']),
        'pull_muted_rules':  random.choice([True, False, 'All']),
        'pull_muted_devices':  random.choice([True, False, 'All']),
        'include_description': random.choice([True, False]),
        'include_signature': random.choice([True, False]),
        'include_events': random.choice([True, False]),
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # Test both start and end dates in the past
    polling_args['start_date'] = date_past_1_str
    polling_args['end_date'] = date_future_1_str

    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_end_date = str_to_utc_datetime(history['end_date'], DEFAULT_DATE_FORMAT)
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert history['start_date'] == date_past_1_str
    assert h_end_date - expected_checkpoint < timedelta(seconds=1)
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint == h_end_date
    assert not context.get_history()


def test_get_splitted_context_past_start_date_no_end_date(mocker):
    random_days_past_1 = random.randint(2, 100)

    now = datetime.now(tz=timezone.utc)
    date_past_1 = now - timedelta(days=random_days_past_1)
    date_past_1_str = datetime_to_utc_str(date_past_1, DEFAULT_DATE_FORMAT)

    random_delay = random.randint(1, 60)
    expected_checkpoint = now - timedelta(minutes=random_delay)

    polling_args = {
        'polling_delay': random_delay,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': random.choice([True, False, 'All']),
        'pull_muted_rules':  random.choice([True, False, 'All']),
        'pull_muted_devices':  random.choice([True, False, 'All']),
        'include_description': random.choice([True, False]),
        'include_signature': random.choice([True, False]),
        'include_events': random.choice([True, False]),
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # Test both start and end dates in the past
    polling_args['start_date'] = date_past_1_str

    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_end_date = str_to_utc_datetime(history['end_date'], DEFAULT_DATE_FORMAT)
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert history['start_date'] == date_past_1_str
    assert h_end_date - expected_checkpoint < timedelta(seconds=1)
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint == h_end_date
    assert not context.get_history()


def test_get_splitted_context_no_start_date_no_end_date(mocker):
    now = datetime.now(tz=timezone.utc)
    random_delay = random.randint(1, 60)
    expected_checkpoint = now - timedelta(minutes=random_delay)

    polling_args = {
        'polling_delay': random_delay,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': random.choice([True, False, 'All']),
        'pull_muted_rules':  random.choice([True, False, 'All']),
        'pull_muted_devices':  random.choice([True, False, 'All']),
        'include_description': random.choice([True, False]),
        'include_signature': random.choice([True, False]),
        'include_events': random.choice([True, False]),
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # Test both start and end dates in the past
    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert history['start_date'] == history['end_date']
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint - expected_checkpoint < timedelta(seconds=1)
    assert not context.get_history()


def test_get_splitted_context_future_start_date_future_end_date(mocker):
    random_days_future_1 = random.randint(1, 99)
    random_days_future_2 = random.randint(random_days_future_1, 100)

    now = datetime.now(tz=timezone.utc)
    date_future_1 = now + timedelta(days=random_days_future_1)
    date_future_1_str = datetime_to_utc_str(date_future_1, DEFAULT_DATE_FORMAT)
    date_future_2 = now + timedelta(days=random_days_future_2)
    date_future_2_str = datetime_to_utc_str(date_future_2, DEFAULT_DATE_FORMAT)

    random_delay = random.randint(1, 60)
    expected_checkpoint = now - timedelta(minutes=random_delay)

    polling_args = {
        'polling_delay': random_delay,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': random.choice([True, False, 'All']),
        'pull_muted_rules':  random.choice([True, False, 'All']),
        'pull_muted_devices':  random.choice([True, False, 'All']),
        'include_description': random.choice([True, False]),
        'include_signature': random.choice([True, False]),
        'include_events': random.choice([True, False]),
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    # Test both start and end dates in the past
    polling_args['start_date'] = date_future_1_str
    polling_args['end_date'] = date_future_2_str

    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_start_date = str_to_utc_datetime(history['start_date'], DEFAULT_DATE_FORMAT)
    h_end_date = str_to_utc_datetime(history['end_date'], DEFAULT_DATE_FORMAT)
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert h_start_date - expected_checkpoint < timedelta(seconds=1)
    assert h_start_date == h_end_date
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint == h_end_date
    assert not context.get_history()

    # Test both start and end dates in the past
    polling_args['start_date'] = date_future_2_str
    polling_args['end_date'] = date_future_1_str

    history_context, context = client.get_splitted_context(polling_args)

    history = history_context.get_history()
    h_start_date = str_to_utc_datetime(history['start_date'], DEFAULT_DATE_FORMAT)
    h_end_date = str_to_utc_datetime(history['end_date'], DEFAULT_DATE_FORMAT)
    h_checkpoint = history_context.get_checkpoint()

    checkpoint_str = context.get_checkpoint()
    checkpoint = str_to_utc_datetime(checkpoint_str, DEFAULT_DATE_FORMAT)

    assert h_start_date - expected_checkpoint < timedelta(seconds=1)
    assert h_start_date == h_end_date
    assert not h_checkpoint or h_checkpoint == history['start_date']

    assert checkpoint == h_end_date
    assert not context.get_history()


def test_poll_history_failure_invalid_dates(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)

    random_days_1 = random.randint(2, 100)
    random_days_2 = random.randint(1, random_days_1)

    now = datetime.now(tz=timezone.utc)
    date_past_1 = datetime_to_utc_str(now - timedelta(days=random_days_1))
    date_past_2 = datetime_to_utc_str(now - timedelta(days=random_days_2))
    date_future_1 = datetime_to_utc_str(now + timedelta(days=random_days_1))

    histories = [
        {
            'start_date': date_past_2,
            'end_date': date_past_1,
        },
        {
            'start_date': date_future_1,
            'end_date': date_past_1,
        },
        {
            'start_date': date_past_1,
            'end_date': date_future_1,
        },
        {
            'start_date': '',
            'end_date': date_past_1,
        },
        {
            'start_date': date_past_1,
            'end_date': '',
        }
    ]
    for history in histories:
        context = ApiContext()
        context.update_history(history)
        for _ in client.poll_history(context=context, args={}):
            assert False


def test_poll_history_succeed_no_enrichment(mocker):
    limit = random.randint(100, 500)
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': True,
        'include_signature': True,
        'include_events': False,
        'limit': limit
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)
    assert mock_validate_token.call_count == 1

    detections_responses = []
    days = random.randint(2, 5)
    for i in range(1, days):
        detections_response = get_fake_detections_response(domain=domain, d_count=limit, r_count=random.randint(1, limit))
        detections_responses.append(detections_response)
    polling_args['start_date'] = f'{days} days ago'

    mock_continuous_calling = mocker.patch('fnc.api.api_client.FncApiClient.continuous_polling', return_value=detections_responses)

    context, _ = client.get_splitted_context(polling_args)

    c = 1
    for detections in client.poll_history(context=context, args=polling_args):
        assert not deep_diff(detections_responses[c-1], detections)
        c += 1

    assert c == days
    assert mock_continuous_calling.call_count == 1

    for c in mock_continuous_calling.call_args_list:
        assert c.kwargs
        args: Dict = c.kwargs.get('args', None)
        ctx: ApiContext = c.kwargs.get('context', None)
        assert args and ctx

        assert not args.get('limit', None)
        start_date = args.get('start_date', None)
        end_date = args.get('end_date', None)
        assert start_date and start_date == context.get_history()['start_date']
        assert end_date and end_date == context.get_history()['end_date']

        assert not deep_diff(ctx.get_history(), context.get_history())
        assert ctx.get_checkpoint() == context.get_history()['end_date']


def test_poll_history_succeed_enrichment(mocker):
    limit = random.randint(100, 500)
    days = 2  # random.randint(2, 5)

    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': False,
        'pull_muted_rules':  False,
        'pull_muted_devices':  False,
        'include_description': False,
        'include_signature': False,
        'include_events': True,
        'limit': limit * days
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain)
    assert mock_validate_token.call_count == 1

    detections_responses = []
    generator_responses = []

    for i in range(0, days):
        responses = []
        detections_response = get_fake_detections_response(domain=domain, d_count=limit, r_count=random.randint(1, limit))
        responses.append(detections_response)
        detections_responses.append(detections_response)
        empty_response = get_empty_detections_response()
        responses.append(empty_response)
        detections_responses.append(empty_response)
        # iter: Iterator[List[Dict]] = Iterator(responses)
        generator_responses.append(iter(responses))

    polling_args['start_date'] = f'{days} days ago'

    mock_continuous_calling = mocker.patch('fnc.api.api_client.FncApiClient.continuous_polling', side_effect=generator_responses)

    context, _ = client.get_splitted_context(polling_args)

    c = 0
    for detections in client.poll_history(context=context, args=polling_args):
        assert not deep_diff(detections_responses[c], detections)
        c += 1

    assert c == days * 2
    assert mock_continuous_calling.call_count == days

    for c in mock_continuous_calling.call_args_list:
        assert c.kwargs
        args: Dict = c.kwargs.get('args', None)
        ctx: ApiContext = c.kwargs.get('context', None)
        assert args and ctx

        assert not args.get('limit', None)
        start_date = args.get('start_date', None)
        end_date = args.get('end_date', None)
        assert start_date and start_date == context.get_history()['start_date']
        assert end_date and end_date == context.get_history()['end_date']

        assert not deep_diff(ctx.get_history(), context.get_history())
        assert ctx.get_checkpoint() == context.get_history()['end_date']
