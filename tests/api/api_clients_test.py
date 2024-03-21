
import copy
import logging
from datetime import datetime

import dateparser
import pytest

from fnc.api.api_client import DetectionApi, EntityApi, FncApiClient, SensorApi
from fnc.api.endpoints import EndpointKey
from fnc.errors import ErrorMessages, ErrorType, FncClientError
from fnc.fnc_client import FncClient
from fnc.global_variables import *
from tests.api.mocks import MockApi, MockEndpoint, MockRestClient
from tests.utils import *


def test_get_url_failure_missing_url_args(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'

    for _, endpoint in endpoints.items():
        # Assert KeyError is raised if any url argument is missing

        url_args: dict = {
            'url_arg_1': url_arg_1,
        }
        with pytest.raises(FncClientError) as e:
            client.get_url(e=endpoint, api=api, url_args=url_args)

        ex: FncClientError = e.value
        data: dict = ex.error_data
        assert isinstance(data['error'], KeyError)


def test_get_url_failure_missing_api_name(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'
    url_arg_2: str = 'fake2'

    for _, endpoint in endpoints.items():
        # Assert KeyError is raised if the api has no name
        url_args: dict = {
            'url_arg_1': url_arg_1,
            'url_arg_2': url_arg_2,
        }

        mocker.patch('tests.api.mocks.MockApi.get_name', return_value='')
        with pytest.raises(FncClientError) as e:
            client.get_url(e=endpoint, api=api, url_args=url_args)

        ex: FncClientError = e.value
        data: dict = ex.error_data
        assert ex.error_type == ErrorType.ENDPOINT_VALIDATION_ERROR
        assert isinstance(data['error'], KeyError)


def test_get_url_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    api = MockApi()
    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
    endpoints = api.get_supported_endpoints()

    url_arg_1: str = 'fake1'
    url_arg_2: str = 'fake2'

    for _, endpoint in endpoints.items():
        endpoint_url = endpoint.get_url()
        url_args: dict = {
            'url_arg_1': url_arg_1,
            'url_arg_2': url_arg_2,
        }
        # Assert it succeed if all the arguments are passed

        endpoint_url = endpoint_url.format(**url_args)
        expected_url = f'https://{api._api_name}.{domain}/{endpoint_url}'
        assert client.get_url(e=endpoint, api=api,
                              url_args=url_args) == expected_url


def test_get_endpoint_if_supported_failure_no_endpoint(mocker):

    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)

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

    unsupported: list = endpoints[slice(0, 1)]
    supported: list = endpoints[slice(1, count)]

    api: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
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

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)
    api2: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
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

    supported: list = get_random_endpoint_keys(size=2)
    api1: MockApi = MockApi(endpoints_keys=supported[slice(0, 1)])
    api2: MockApi = MockApi(endpoints_keys=supported[slice(1, 2)])

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=None)
    client.supported_api = [api1, api2]

    for k in supported:
        key_name = k.title()
        key: EndpointKey = EndpointKey(key_name)

        # Check it succeeds if endpoint is supported by single API
        e, a = client.get_endpoint_if_supported(key)
        e1, a1 = client.get_endpoint_if_supported(key_name)

        assert a and a == a1
        assert e and e == e1


@pytest.mark.skip('This test is in development')
def test_retry_mechanism(mocker):
    assert False


def test_call_endpoint_succeed(mocker):
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    spy_send_request = mocker.spy(rest_client, 'send_request')
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')
    spy_endpoint_validate_response = mocker.spy(endpoint, 'validate_response')

    rand_string = get_random_string(),
    args: dict = {
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
    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
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
    args: dict = {
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

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    client.supported_api = [api1]

    key_name = supported[0].title()
    endpoint_key: EndpointKey = EndpointKey(key_name)
    endpoint: MockEndpoint = api1.get_supported_endpoints().get(endpoint_key)

    spy_endpoint_validate = mocker.spy(endpoint, 'validate')

    rand_string = get_random_string(),
    args: dict = {
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

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
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
    args: dict = {
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

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
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
    args: dict = {
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

    supported: list = get_random_endpoint_keys(size=1)
    api1: MockApi = MockApi(endpoints_keys=supported)

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
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
    args: dict = {
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


@pytest.mark.skip('This test is in development')
def test_continuous_polling_failure(mocker):
    assert False


def test_continuous_polling_including_all(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': True,
        'include_signature': True,
        'include_pdns': True,
        'include_dhcp': True,
        'include_events': True,
        'filter_training_detections': True,
        'start_date': '1 hour'
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    mock_call_endpoint = mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[
                                      copy.deepcopy(fake_detections_response),
                                      copy.deepcopy(fake_fetch_pdns),
                                      copy.deepcopy(fake_fetch_dhcp),
                                      copy.deepcopy(fake_detection_events),
                                      copy.deepcopy(empty_detection_events),
                                      copy.deepcopy(empty_detections_response)])

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    assert mock_validate_token.call_count == 1

    client.supported_api = [DetectionApi, SensorApi, EntityApi]

    call = 0
    for response in client.continuous_polling(args=polling_args):
        call += 1
        if call == 1:
            assert len(response['detections']) == 1
            detection = response['detections'][0]
            assert 'rule_uuid' in detection and detection.get('rule_uuid') == fake_rule_id
            assert 'rule_name' in detection and detection.get('rule_name') == fake_rule_name
            assert 'rule_severity' in detection and detection.get('rule_severity') == fake_rule_severity
            assert 'rule_confidence' in detection and detection.get('rule_confidence') == fake_rule_confidence
            assert 'rule_category' in detection and detection.get('rule_category') == fake_rule_category
            assert 'rule_description' in detection and detection.get('rule_description') == fake_rule_description
            assert 'rule_signature' in detection and detection.get('rule_signature') == fake_rule_signature

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

    assert mock_call_endpoint.call_count == 6

    i = 0
    expected_endpoints = [EndpointKey.GET_DETECTIONS, EndpointKey.GET_ENTITY_PDNS, EndpointKey.GET_ENTITY_DHCP,
                          EndpointKey.GET_DETECTION_EVENTS, EndpointKey.GET_DETECTION_EVENTS, EndpointKey.GET_DETECTIONS]
    expected_args = [
        {'offset': 0, 'status': polling_args.get('status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'},
        {'entity': fake_ip},
        {'entity': fake_ip},
        {'detection_uuid': fake_detection_id, 'offset': 0},
        {'detection_uuid': fake_detection_id, 'offset': POLLING_MAX_DETECTION_EVENTS},
        {'offset': POLLING_MAX_DETECTIONS, 'status': polling_args.get(
            'status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'}
    ]
    for c in mock_call_endpoint.call_args_list:
        assert c.kwargs
        assert expected_endpoints[i] == c.kwargs.get('endpoint', None)
        received_args = c.kwargs.get('args', {})
        assert all(k in received_args and received_args.get(k) == expected_args[i].get(k) for k in expected_args[i])
        i += 1


def test_continuous_polling_including_nothing(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  random.choice(['active', 'resolved']),
        'pull_muted_detections': 'ALL',
        'pull_muted_rules':  'ALL',
        'pull_muted_devices':  'ALL',
        'include_description': False,
        'include_signature': False,
        'include_pdns': False,
        'include_dhcp': False,
        'include_events': False,
        'filter_training_detections': False
    }
    api_token = 'fake_api_token'
    domain = 'fake_domain'
    agent = 'fake_agent'

    rest_client = MockRestClient()
    mock_call_endpoint = mocker.patch('fnc.api.api_client.FncApiClient.call_endpoint', side_effect=[
                                      copy.deepcopy(fake_detections_response), copy.deepcopy(empty_detections_response)])

    mock_validate_token = mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncClient.get_api_client(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
    assert mock_validate_token.call_count == 1

    client.supported_api = [DetectionApi, SensorApi, EntityApi]
    client.get_logger().set_level(level=logging.DEBUG)
    call = 0
    for response in client.continuous_polling(args=polling_args):
        call += 1
        if call == 1:
            assert len(response['detections']) == 1
            detection = response['detections'][0]
            assert 'rule_uuid' in detection and detection.get('rule_uuid') == fake_rule_id
            assert 'rule_name' in detection and detection.get('rule_name') == fake_rule_name
            assert 'rule_severity' in detection and detection.get('rule_severity') == fake_rule_severity
            assert 'rule_confidence' in detection and detection.get('rule_confidence') == fake_rule_confidence
            assert 'rule_category' in detection and detection.get('rule_category') == fake_rule_category
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
        {'offset': 0, 'status': polling_args.get('status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'},
        {'offset': POLLING_MAX_DETECTIONS, 'status': polling_args.get(
            'status'), 'sort_by': 'device_ip', 'sort_order': 'asc', 'include': 'rules, indicators'}
    ]
    for c in mock_call_endpoint.call_args_list:
        assert c.kwargs
        assert expected_endpoints[i] == c.kwargs.get('endpoint', None)
        received_args = c.kwargs.get('args', {})
        assert all(k in received_args and received_args.get(k) == expected_args[i].get(k) for k in expected_args[i])
        i += 1
