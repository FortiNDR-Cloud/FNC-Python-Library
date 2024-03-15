import requests
import requests_mock

from fnc.api.endpoints import ArgumentDefinition, Endpoint, EndpointKey, FncApi
from fnc.api.rest_clients import FncRestClient
from fnc.tests.api.utils import *


class MockEndpoint(Endpoint):
    version: str = 'expected_version'
    endpoint: str = 'expected_endpoint/{url_arg_1}/{url_arg_2}'

    default_values: dict = {}

    def __init__(self, key=None):
        self._key = key if key else EndpointKey(
            get_random_endpoint_keys(size=1)[0].title())

    def get_endpoint_key(self) -> EndpointKey:
        return self._key

    def get_control_args(self) -> dict:
        return {
            'method': 'METHOD'
        }

    def get_url_args(self) -> list:
        return ['url_arg_1', 'url_arg_2']

    def get_body_args(self) -> dict:
        return {
            'body_arg_required':               ArgumentDefinition(required=True, multiple=False),
            'body_arg_multiple':               ArgumentDefinition(required=False, multiple=True),
            'body_arg_allowed':                ArgumentDefinition(
                required=False, multiple=False, allowed=['expected_1', 'expected_2', 'expected_3']
            ),
            'body_arg_multiple_and_allowed':   ArgumentDefinition(
                required=False, multiple=True, allowed=['expected_1', 'expected_2', 'expected_3']
            ),
        }

    def get_query_args(self) -> dict:
        return {
            'query_arg_required':               ArgumentDefinition(required=True, multiple=False),
            'query_arg_multiple':               ArgumentDefinition(required=False, multiple=True),
            'query_arg_allowed':                ArgumentDefinition(
                required=False, multiple=False, allowed=['expected_1', 'expected_2', 'expected_3']
            ),
            'query_arg_multiple_and_allowed':   ArgumentDefinition(
                required=False, multiple=True, allowed=['expected_1', 'expected_2', 'expected_3']
            ),
        }

    def get_response_fields(self) -> list[str]:
        return ['response_field_1', 'response_field_2']


class MockApi(FncApi):
    _api_name = 'mock_api'
    _supported_endpoints: dict

    def __init__(self, endpoints_keys: list = []):

        keys = endpoints_keys if endpoints_keys else get_random_endpoint_keys()
        endpoints = [EndpointKey(key.title()) for key in keys]
        values = list(map(lambda x: MockEndpoint(x), endpoints))
        self._supported_endpoints = dict(
            map(lambda i, j: (i, j), endpoints, values))

    def get_supported_endpoints(self) -> dict:

        return self._supported_endpoints


class MockRestClient(FncRestClient):
    validate_request_args: dict = {}
    send_request_args: dict = {}

    def validate_request(self, req_args: dict):
        self.validate_request_args = req_args

    def send_request(self, req_args: dict):
        self.send_request_args = req_args

        url = req_args['url']
        expected = {
            'response_field_1': get_random_string(),
            'response_field_2': get_random_string(),
        }

        with requests_mock.Mocker() as mock_request:
            mock_request.get(url=url, json=expected, status_code=200)
            return requests.get(url)

    def client_error_handler(self, res):
        raise NotImplementedError()

    def _implement_retry(self):
        raise NotImplementedError()
