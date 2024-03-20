
from datetime import datetime

import dateparser
import pytest

from fnc.api.api_client import Context, DetectionApi, EntityApi, FncApiClient, SensorApi
from fnc.api.endpoints import EndpointKey
from fnc.errors import ErrorType, FncClientError
from fnc.global_variables import *
from tests.api.mocks import MockApi, MockEndpoint, MockRestClient
from tests.utils import *


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
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
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
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=None)
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

    unsupported: list = endpoints[slice(0, 1)]
    supported: list = endpoints[slice(1, count)]

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

    supported: list = get_random_endpoint_keys(size=1)
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

    supported: list = get_random_endpoint_keys(size=2)
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
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)
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


@pytest.mark.skip('This test is in development')
def test_call_endpoint_failure(mocker):
    assert False


@pytest.mark.skip('This test is in development')
def test_continuous_polling_failure(mocker):
    assert False


@pytest.mark.skip('This test is in development')
def test_continuous_polling(mocker):
    polling_args = {
        'polling_delay': 10,
        'status':  'active',
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
    spy_send_request = mocker.spy(rest_client, 'send_request')
    spy_validate_request = mocker.spy(rest_client, 'validate_request')

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')
    client = FncApiClient(name=agent, api_token=api_token, domain=domain, rest_client=rest_client)

    client.supported_api = [DetectionApi, SensorApi, EntityApi]
    i = 0
    checkpoint = ''

    running_time = datetime.now()
    end_time = dateparser.parse('in 30 minutes')
    while running_time < end_time:
        client.get_logger().info(f"Running time = {running_time}")
        client.get_logger().info(f"Running until {end_time}")

        context = Context()
        client.get_logger().info(context.get_checkpoint())
        client.get_logger().info(context.get_polling_args())
        context.update_checkpoint(checkpoint=checkpoint)

        for response in client.continuous_polling(context=context, args=polling_args):
            client.get_logger().info("-------------------------------------")
            client.get_logger().info(
                f"DETECTIONS: {len(response['detections'])}")
            for detection in response['events']:
                client.get_logger().info(
                    f"{len(response['events'][detection])} EVENTS for {detection}")
            client.get_logger().info(
                f'CHECKPOINT: {context.get_checkpoint()}')
            client.get_logger().info("-------------------------------------")

        checkpoint = context.get_checkpoint()
        context.clear_args()
        running_time = datetime.now()