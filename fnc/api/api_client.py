
import json
import traceback
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterator, List, Tuple, Union

from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

from fnc.api.endpoints import DetectionApi, Endpoint, EndpointKey, EntityApi, FncApi, SensorApi
from fnc.global_variables import (CLIENT_DEFAULT_DOMAIN, CLIENT_DEFAULT_USER_AGENT, CLIENT_MAX_AGE_HOURS, CLIENT_NAME, CLIENT_PROTOCOL,
                                  CLIENT_VERSION, DEFAULT_DATE_FORMAT, POLLING_DEFAULT_DELAY, POLLING_MAX_DETECTION_EVENTS,
                                  POLLING_MAX_DETECTIONS, REQUEST_DEFAULT_TIMEOUT, REQUEST_DEFAULT_VERIFY, REQUEST_MAXIMUM_RETRY_ATTEMPT)
from fnc.utils import datetime_to_utc_str, str_to_utc_datetime

from ..errors import ErrorMessages, ErrorType, FncClientError
from ..logger import BasicLogger, FncClientLogger
from .rest_clients import BasicRestClient, FncRestClient


class EntityDetailsCacheRecord:
    entityDetails: dict
    added_timestamp: datetime
    entity: str

    def __init__(self, entity: str, entityDetails: dict):
        self.entity = entity
        self.entityDetails = entityDetails
        self.added_timestamp = datetime.now()

    # --- Getter methods ---
    def get_entity(self) -> str:
        return self.entity

    def get_entity_details(self) -> dict:
        return self.entityDetails

    def get_added_timestamp(self) -> datetime:
        return self.added_timestamp


class EntityDetailsCache:
    cache: dict

    def __init__(self):
        self.cache: dict[str, EntityDetailsCacheRecord] = {}

    def add_record(self, entity: str, entityDetails: dict):
        record = EntityDetailsCacheRecord(
            entity=entity,
            entityDetails=entityDetails
        )

        self.cache[entity] = record

    def is_record_valid(self, entity: str) -> bool:
        if entity not in self.cache:
            return False

        record = self.cache[entity]
        max_age_delta = timedelta(hours=CLIENT_MAX_AGE_HOURS)
        expiration_time = datetime.now() - max_age_delta

        if record.added_timestamp < expiration_time:
            del self.cache[entity]
            return False
        else:
            return True

    def get_record(self, entity: str) -> Dict:
        if self.is_record_valid(entity):
            return self.cache[entity].get_entity_details()
        else:
            return None

    def get_all(self) -> Dict:
        res = {}
        for entity in self.cache.keys():
            # Check if the record is still valid (and delete if expired)
            if self.is_record_valid(entity):
                record = self.cache.get(entity)
                res[entity] = record.get_entity_details()
        return res

    def clear_cache(self):
        self.cache.clear()


class MetricName(Enum):
    CONTINUOUS_POLLING_EXECUTION = "Polling executions"

    DETECTIONS_REQUESTED = "Get Detections requests"
    DETECTIONS_LIMIT_VERIFIED = "GetDetections requests to verify limit"
    DETECTIONS_FAILED_REQUEST = "GetDetections failed requests"
    DETECTIONS_RETRIEVED = "Detections retrieved"

    DETECTION_EVENTS_REQUESTED = "Get Detection's Associated Events requests"
    DETECTION_EVENTS_FAILED_REQUEST = "Get Detection's Associated Events failed requests"
    DETECTION_EVENTS_RETRIEVED = "Detection's Associated Events retrieved"

    ENTITY_ENRICHMENT_REQUESTED = "Get Entity Information Requests"
    FAILED_PDNS_REQUEST = "Entity's Pdns failed requests"
    FAILED_DHCP_REQUEST = "Entity's Dhcp failed requests"
    FAILED_VT_REQUEST = "Entity's Virus Total failed requests"
    ENTITY_ENRICHMENT_FROM_CACHE = "Entity Information Retrieved from Cache"


class Metrics:
    def __init__(self, counters: Dict[str, int] = {}):
        self.counters: Dict[str, int] = counters or {}

    def increment(self, metric_name: MetricName, amount: int = 1):
        """Increments a specific counter."""
        key = metric_name
        if key not in self.counters:
            self.counters[key] = 0

        self.counters[key] += amount

    def get_value(self, metric_name: MetricName) -> int:
        """Returns the current count for a specific metric."""
        return self.counters.get(metric_name.value, 0)

    def reset_all(self):
        """Resets all stored counters to zero."""
        self.counters = {key: 0 for key in self.counters}

    def merge(self, source_metrics: 'Metrics'):
        for key, value in source_metrics.counters.items():
            self.counters[key] = self.counters.get(key, 0) + value

    def get_all(self):
        """Returns a copy of all counters."""
        return self.counters.copy()

    def get_metric_report(self, title: str = "Metrics Report") -> str:
        """
        Generates a string report of all counters based on the logic provided.
        """
        report_lines = [f"\n--- {title} ---"]
        report_lines.extend(self.get_detections_report())

        detections_retrieved_count = self.counters.get(MetricName.DETECTIONS_RETRIEVED, 0)
        if detections_retrieved_count > 0:
            report_lines.extend(self.get_detections_events_report())
            report_lines.extend(self.get_entities_report())

        return "\n".join(report_lines)

    def get_detections_report(self) -> list[str]:
        report_lines = [f"      - Detection's Report ---"]

        detection_request_count = self.counters.get(MetricName.DETECTIONS_REQUESTED, 0)
        limit_verified_count = self.counters.get(MetricName.DETECTIONS_LIMIT_VERIFIED, 0)
        failed_requests_count = self.counters.get(MetricName.DETECTIONS_FAILED_REQUEST, 0)
        detections_retrieved_count = self.counters.get(MetricName.DETECTIONS_RETRIEVED, 0)

        if detections_retrieved_count > 0:
            report_lines.append(f"          {detections_retrieved_count} detections were retrieved in {detection_request_count} requests.")
        else:
            report_lines.append(f"          No detections were retrieved in {detection_request_count} requests.")

        if limit_verified_count > 0:
            report_lines.append(f"          {limit_verified_count} of the requests were to verified the limit.")

        if failed_requests_count > 0:
            report_lines.append(f"          {failed_requests_count} detections requests failed.")

        return report_lines

    def get_detections_events_report(self) -> list[str]:
        report_lines = [f"      - Detection's Associated Events Report ---"]

        detection_events_requests_count = self.counters.get(MetricName.DETECTION_EVENTS_REQUESTED, 0)
        failed_requests_count = self.counters.get(MetricName.DETECTION_EVENTS_FAILED_REQUEST, 0)
        detection_events_retrieved_count = self.counters.get(MetricName.DETECTION_EVENTS_RETRIEVED, 0)

        if detection_events_retrieved_count > 0:
            report_lines.append(
                f"          {detection_events_retrieved_count} detection's associated events were retrieved in {detection_events_requests_count} requests.")
        else:
            report_lines.append(f"          No detection's associated events were retrieved in {detection_events_requests_count} requests.")

        if failed_requests_count > 0:
            report_lines.append(f"          {failed_requests_count} detection's associated events requests failed.")

        return report_lines

    def get_entities_report(self) -> list[str]:
        report_lines = [f"      - Entities Information Report ---"]

        entity_enrichment_request_count = self.counters.get(MetricName.ENTITY_ENRICHMENT_REQUESTED, 0)
        entity_enrichment__from_cache_count = self.counters.get(MetricName.ENTITY_ENRICHMENT_FROM_CACHE, 0)
        failed_pdns_requests_count = self.counters.get(MetricName.FAILED_PDNS_REQUEST, 0)
        failed_dhcp_requests_count = self.counters.get(MetricName.FAILED_DHCP_REQUEST, 0)
        failed_vt_requests_count = self.counters.get(MetricName.FAILED_VT_REQUEST, 0)

        if entity_enrichment_request_count > 0:
            report_lines.append(
                f"          {entity_enrichment_request_count} entities were enriched.")

            report_lines.append(
                f"          {entity_enrichment_request_count - entity_enrichment__from_cache_count} were requested and {entity_enrichment__from_cache_count} were retrieved from cache.")
        else:
            report_lines.append("          No entity was enriched.")

        if failed_pdns_requests_count > 0:
            report_lines.append(f"          {failed_pdns_requests_count} Pdns requests failed.")

        if failed_dhcp_requests_count > 0:
            report_lines.append(f"          {failed_dhcp_requests_count} Dhcp requests failed.")

        if failed_vt_requests_count > 0:
            report_lines.append(f"          {failed_vt_requests_count} Vt requests failed.")

        return report_lines


class ApiContext:
    _polling_args: Dict
    _entity_details_cache: EntityDetailsCache
    _global_metric: Metrics
    _sub_metric: Metrics

    def __init__(self):
        self._checkpoint = ''
        self._history = {}
        self._polling_args = {}
        self._entity_details_cache = EntityDetailsCache()
        self.global_metrics = Metrics()
        self.sub_metrics = Metrics()

    def get_entity_details_cache(self) -> EntityDetailsCache:
        return self._entity_details_cache

    def set_entity_details_cache(self, cache: EntityDetailsCache) -> EntityDetailsCache:
        self._entity_details_cache = cache or self._entity_details_cache

    def update_history(self, history: Dict):
        self._history = history or None

    def get_history(self):
        return self._history

    def get_remaining_history(self):
        history = self._history.copy()
        if self._checkpoint:
            history['start_date'] = self._checkpoint

        return history

    def update_checkpoint(self, checkpoint: str):
        self._checkpoint = checkpoint

    def get_checkpoint(self):
        return self._checkpoint

    def update_polling_args(self, args: Dict):
        self._polling_args = args or None

    def get_polling_args(self):
        return self._polling_args

    def clear_args(self):
        self._polling_args = {}

    # --- Metric Collection Methods ---
    def record_metric(self, metric_name: MetricName, amount: int = 1):
        """
        Records the metric to BOTH the sub-metric and the global metric.
        """
        # Global Metric update
        self.global_metrics.increment(metric_name, amount)

        # Sub-Metric update
        self.sub_metrics.increment(metric_name, amount)

    def get_sub_metrics(self) -> Metrics:
        """
        Returns the current accumulated sub-metrics.
        """
        return Metrics(self.sub_metrics.get_all())

    def reset_sub_metrics(self):
        """
        Resets all sub-metrics to zero.
        """
        self.sub_metrics.reset_all()

    def get_global_metrics(self) -> Metrics:
        """
        Returns the overall cumulative global metrics.
        """
        return Metrics(self.global_metrics.get_all())


class FncApiClient:

    supported_api: List[FncApi] = [SensorApi(), DetectionApi(), EntityApi()]

    domain: str
    protocol: str = CLIENT_PROTOCOL
    api_token: str
    user_agent: str
    rest_client: FncRestClient
    logger: FncClientLogger
    default_control_args: Dict
    entityDetailsCache: EntityDetailsCache

    def __init__(
        self,
        name: str = None,
        api_token: str = None,
        domain: str = None,
        rest_client: FncRestClient = None,
        logger: FncClientLogger = None
    ):
        name = f'{name}-api'
        self.user_agent = f"{CLIENT_DEFAULT_USER_AGENT}-{name}"
        self.logger = logger or BasicLogger(name=self.user_agent)

        self.rest_client = rest_client or BasicRestClient()
        self.rest_client.set_logger(self.logger)

        self.logger.info(f"Initializing {CLIENT_NAME} version {CLIENT_VERSION}.")

        self.api_token = api_token
        self.domain = domain or CLIENT_DEFAULT_DOMAIN

        self.set_default_control_args()

        self.logger.info(f"User_Agent was set to: {self.user_agent}")
        self._validate_api_token()

    def _validate_api_token(self):
        """
        This method perform a call to the Get_Detections endpoint with limit =1 to validate
        the provided API Token
        """
        self.logger.info("Verifying API Token.")

        # Call Get_Detections endpoint with limit = 1
        try:
            _ = self.call_endpoint(EndpointKey.GET_SENSORS, {})
            self.logger.info("The API Token has been successfully validated.")
        except FncClientError as e:
            self.logger.error(f"API Token validation failed due to {e}.")
            raise FncClientError(
                error_type=ErrorType.CLIENT_API_TOKEN_VALIDATION_ERROR,
                error_message=ErrorMessages.CLIENT_API_TOKEN_VALIDATION_ERROR,
                error_data={'error': e},
                exception=e
            )

    def get_logger(self):
        return self.logger

    def _get_portal_url(self) -> str:
        """
        This method construct the portal url by mapping icebrg.io to fortindr.forticloud.com.
        """

        domain = self.domain
        domain = domain.replace('icebrg.io', 'fortindr.forticloud.com')
        # Prepare the url
        if domain.startswith('-uat'):
            # To allow use of uat environment
            url = f"{self.protocol}://portal{domain}"
        else:
            url = f"{self.protocol}://portal.{domain}"

        return url

    def get_url(self, e: Endpoint, api: FncApi, url_args: Dict = {}) -> str:
        """
        This method construct the full url by gathering all the required information from the API and the endpoint
        and evaluating any existing argument in the url.

        Args:
            e (Endpoint): The definition of the endpoint that want to be reached with this url.
            api (FncApi): The definition of the API supporting the provided endpoint
            url_args (Dict, optional): the values for any existing argument in the url. Defaults to {}.

        Raises:
            FncApiClientError: Error_Type.API_VALIDATION_ERROR is raised if the provided API does not have the attribute name defined.
            FncApiClientError: Error_Type.ENDPOINT_VALIDATION_ERROR is raised if the url part of the endpoint cannot be retrieved.

        Returns:
            str: Returns the full url to reach the provided endpoint after evaluate any existing argument.
        """
        try:
            api_name = api.get_name()

            # Verify that the API's name was defined
            if not api_name:
                self.logger.error(
                    f"The API supporting endpoint {e.get_endpoint_key().name} is missing its name. \n" +
                    "The API's name is required to form the endpoint url."
                )

                raise KeyError(["API's name"])

            # Verify that the endpoint's url was defined
            endpoint = e.get_url()

            # Prepare the url
            if self.domain.startswith('-uat'):
                # To allow use of uat environment
                url = f"{self.protocol}://{api_name}{self.domain}/{endpoint}"
            else:
                url = f"{self.protocol}://{api_name}.{self.domain}/{endpoint}"

            full_url = ""

            # Evaluate any argument present in the url and return the resulted full url
            full_url = url.format(**url_args)
            self.logger.debug(f"URL successfully created: [{url}]")
        except KeyError as ex:
            # Some of the required arguments to format the url were not provided
            raise FncClientError(
                error_type=ErrorType.ENDPOINT_VALIDATION_ERROR,
                error_message=ErrorMessages.ENDPOINT_URL_CANNOT_BE_FORMED,
                error_data={'endpoint': e.get_endpoint_key().name,
                            'error': ex},
                exception=ex
            )
        return full_url

    def get_endpoint_if_supported(self, endpoint: Union[str, EndpointKey]) -> Tuple[Endpoint, FncApi]:
        """
        This method verify if the endpoint is supported by any of the defined APIs.
        If the endpoint is supported the endpoint's definition and the API are returned.

        Args:
            endpoint (Union[str, EndpointKey]): The endpoint to be retrieved. It can be passed as the EndpointKey or just the name.

        Raises:
            FncApiClientError: Error_Type ENDPOINT_ERROR if the Endpoint was not provided, defined or it is not supported.
            FncApiClientError: Error_Type ENDPOINT_VALIDATION_ERROR if the provided endpoint is supported by most than one API.

        Returns:
            Tuple[Endpoint, FncApi]: Returns the Endpoint's definition and the API that supports it
        """

        k = None
        api: FncApi = None

        # Raise unsupported Error if no endpoint was provided
        if not endpoint:
            self.logger.error("The endpoint was not provided")
            raise FncClientError(
                error_type=ErrorType.ENDPOINT_ERROR,
                error_message=ErrorMessages.ENDPOINT_NOT_SUPPORTED,
                error_data={'endpoint': ''}
            )

        # Get the EndpointKey if it was provided as str
        if isinstance(endpoint, str):
            endpoint = endpoint.title()
            self.logger.debug(f"Retrieving endpoint {endpoint}")

            try:
                # Verify the EndpointKey was defined for the received endpoint
                k = EndpointKey(endpoint)
            except Exception:
                # Raise unsupported Error if the endpoint has not been defined
                self.logger.error(f"The endpoint ({endpoint}) is not defined. Verify that the spelling correspond with the EndpointKey.")
                raise FncClientError(
                    error_type=ErrorType.ENDPOINT_ERROR,
                    error_message=ErrorMessages.ENDPOINT_NOT_SUPPORTED,
                    error_data={'endpoint': endpoint}
                )
        else:
            self.logger.debug(f"Retrieving endpoint {endpoint.name}")
            k = endpoint

        # Get any API supporting the provided endpoint
        filtered: List = list(
            filter(lambda a: k in a.get_supported_endpoints(), self.supported_api))
        # filtered: List = [
        #     supported_endpoint for supported_api in self.supported_api
        #     for supported_endpoint in supported_api.get_supported_endpoints()
        # ]

        for a in filtered:
            if api:
                # Raise a Validation Error if the endpoint is supported by most than one API.
                raise FncClientError(
                    error_type=ErrorType.ENDPOINT_VALIDATION_ERROR,
                    error_message=ErrorMessages.ENDPOINT_MULTIPLE_SUPPORTED,
                    error_data={'endpoint': k}
                )
            api = a

        if api:
            e: Endpoint = api.get_supported_endpoints()[k]
            e.set_Logger(self.logger)
            return e, api
        else:
            # Raise Unsupported Error since the endpoint is not supported.
            raise FncClientError(
                error_type=ErrorType.ENDPOINT_ERROR,
                error_message=ErrorMessages.ENDPOINT_NOT_SUPPORTED,
                error_data={'endpoint': endpoint}
            )

    def _get_headers(self) -> Dict:
        """
        This method returns the dictionary containing all the required headers.

        Returns:
            Dict: Dictionary containing the headers
        """
        return {
            'Authorization': f'IBToken {self.api_token}',
            'User-Agent': self.user_agent,
            'Content-Type': 'application/json',
        }

    def set_default_control_args(self, args: Dict = None):
        self.default_control_args: Dict = {
            'method': 'GET',
            'verify': REQUEST_DEFAULT_VERIFY,
            'timeout': REQUEST_DEFAULT_TIMEOUT,
        }
        if args:
            self.default_control_args = {**self.default_control_args, **args}

    def get_default_control_args(self) -> Dict:
        """
        This method returns a dictionary containing all the default control arguments used by the client.

        Returns:
            Dict: Dictionary containing the default control arguments
        """
        args = self.default_control_args.copy()
        args.update({'headers': self._get_headers()})
        return args

    def _prepare_request(self, endpoint: Union[str, EndpointKey], args: Dict, reduced_log: bool = False) -> Tuple[Endpoint, Dict]:
        """
        This method receive an endpoint and a dictionary of arguments it then verify that the endpoint is supported,
        that any required argument is present and that there is no unexpected argument. If the validation is passed,
        the arguments are separated as per where are they expected and the full url is computed replacing any argument
        with its value.

        Args:
            endpoint (Union[str, EndpointKey]): endpoint to be called
            args (Dict): arguments to be passed with the request

        Raises:
            FncApiClientError: Reraise any exception raised during the endpoint validation or the calculation of the full url.

        Returns:
            Tuple[Endpoint, Dict]: Returns the definition of the endpoint to be called and a dictionary with the arguments splitted as:
            'url_args', 'query_args', 'body_args' and 'control_args'
        """
        e: Endpoint = None
        api: FncApi = None

        self.logger.debug(f'Preparing request to endpoint {endpoint}')
        # Verify the endpoint is supported
        try:
            e, api = self.get_endpoint_if_supported(endpoint)

            #  Evaluate and Validate the Endpoint
            e_args = e.evaluate(args=args.copy())

            e.validate(to_validate=e_args)

            # Gather all the request's control arguments
            control_args = self.get_default_control_args()
            if 'control_args' in e_args:
                # Adding the control's arguments received from the endpoint since they take precedence
                control_args.update(e_args['control_args'])
                e_args['control_args'] = control_args

            # Compute and update the url with api and endpoint information
            url_args = e_args.get('url_args', {})
            full_url = self.get_url(e=e, api=api, url_args=url_args)
            e_args['control_args']['url'] = full_url
        except FncClientError as ex:
            self.logger.error(f"Request preparation failed for endpoint {e.get_endpoint_key().name} due to {ex}")
            raise ex
        except Exception as ex:
            self.logger.error(
                f"Request preparation failed unexpectedly.\n [{str(ex)}]")
            raise FncClientError(
                error_type=ErrorType.GENERIC_ERROR,
                error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
                error_data={'error': ex},
                exception=ex
            )

        return (e, e_args)

    def _get_rest_client_arguments(self, req_args: Dict = None, query_args: Dict = None, body_args: Any = None) -> Dict:
        """
        This method get the request arguments and create a new dictionary with the arguments as they are expected by the Rest Client.

        Args:
            req_args (Dict, optional): Arguments that control the request. Defaults to None.
            query_args (Dict, optional): Arguments to be passed in the query string. Defaults to None.
            body_args (Any, optional): Arguments to be passed in the body. Defaults to None.

        Returns:
            Dict: New dictionary with the arguments as they are expected by the Rest Client
        """
        requests_args = {}
        requests_args.update(req_args)
        if query_args:
            requests_args['params'] = query_args
        if body_args:
            if isinstance(body_args, (Dict, List)):
                requests_args['json'] = body_args
            else:
                requests_args['data'] = str(body_args)
        return requests_args

    def _map_error(self, error: Exception) -> FncClientError:
        masked_url = '???'

        if isinstance(error, FncClientError):
            return error
        elif isinstance(error, ConnectionError):
            return FncClientError(
                ErrorType.REQUEST_CONNECTION_ERROR,
                ErrorMessages.REQUEST_CONNECTION_ERROR,
                {'url': masked_url, 'error': error}
            )
        elif isinstance(error, Timeout):
            return FncClientError(
                ErrorType.REQUEST_TIMEOUT_ERROR,
                ErrorMessages.REQUEST_TIMEOUT_ERROR,
                {'url': masked_url, 'error': error}
            )
        elif isinstance(error, HTTPError):
            return FncClientError(
                ErrorType.REQUEST_HTTP_ERROR,
                ErrorMessages.REQUEST_HTTP_ERROR,
                {'url': masked_url, 'error': error}
            )
        elif isinstance(error, RequestException):
            return FncClientError(
                ErrorType.REQUEST_ERROR,
                ErrorMessages.REQUEST_ERROR,
                {'url': masked_url, 'error': error}
            )
        else:
            return FncClientError(
                ErrorType.GENERIC_ERROR,
                ErrorMessages.GENERIC_ERROR_MESSAGE,
                {'error': error}
            )

    def _is_retry_needed(self, error: Exception, attempt: int) -> bool:
        need_retry = False

        if error:
            if not isinstance(error, FncClientError):
                error = self._map_error(error)

            if error.error_type == ErrorType.ENDPOINT_RESPONSE_VALIDATION_ERROR:
                status = error.error_data.get('status', None)
                need_retry = not status or status >= 500
            else:
                need_retry: bool = error.error_type in [
                    ErrorType.REQUEST_CONNECTION_ERROR,
                    ErrorType.REQUEST_TIMEOUT_ERROR,
                    ErrorType.GENERIC_ERROR
                ]

        return need_retry and attempt <= REQUEST_MAXIMUM_RETRY_ATTEMPT

    def call_endpoint(self, endpoint: Union[str, EndpointKey], args: Dict, reduced_log: bool = False) -> Dict:
        """
        This method receives an endpoint and a dictionary of arguments. It will prepare
        and send the request to the received endpoint as well as validate the returned
        response returning the json response if it is valid

        Args:
            endpoint (Union[str, EndpointKey]): Endpoint to where to send the request
            args (Dict): dictionary with all the argument's values that need to passed with the request

        Raises:
            FncApiClientError: If anything fails during the request

        Returns:
            Dict:  Response's json
        """
        # We avoid printing info and debug logs when the continuous calling is enriching
        # detections with associated events

        endpoint_key_name = endpoint if isinstance(endpoint, str) else endpoint.name
        need_retry = False
        attempt = 0

        args = args or {}
        args = args.copy()

        while attempt == 0 or need_retry:
            if need_retry and not reduced_log:
                self.logger.info(f"Retrying...... [attempt #{attempt}]")

            response = None
            error = None

            e: Endpoint = None
            try:
                e, e_args = self._prepare_request(endpoint=endpoint, args=args)
                req_args = self._get_rest_client_arguments(
                    req_args=e_args['control_args'], body_args=e_args['body_args'], query_args=e_args['query_args']
                )

                if not reduced_log:
                    self.logger.info(f"Sending request to {e.get_endpoint_key().name} endpoint.")

                self.rest_client.validate_request(req_args)
                response = self.rest_client.send_request(req_args=req_args)

                res_json = e.validate_response(response)
                if not reduced_log:
                    self.logger.info("Response successfully validated.")

            except Exception as ex:
                self.logger.error(f"The request to {endpoint_key_name} endpoint failed due to:")

                self.logger.error(traceback.format_exc())
                error = ex

            attempt += 1
            need_retry = self._is_retry_needed(error, attempt)

        if error:
            if attempt > REQUEST_MAXIMUM_RETRY_ATTEMPT:
                self.logger.error(
                    "Maximum number of retry attempts has been reached.")
            raise self._map_error(error)

        return res_json

#######################################
#
#
#   Continuous Polling Methods
#
#
########################################

    def _get_and_validate_search_window(
        self, start_date_str: str = None,
        end_date_str: str = None,
        polling_delay: int = None,
        checkpoint: str = None
    ) -> Tuple[datetime, datetime]:
        # We try to get the start_date from the arguments or the checkpoint.
        # If none of them is provided we use the utc now - delay
        start_date_str = checkpoint or start_date_str or ""

        # If the polling_delay is not provided, we use the default polling delay
        polling_delay = polling_delay or POLLING_DEFAULT_DELAY

        now = datetime.now(tz=timezone.utc)
        minutes: int = int(polling_delay)
        end_date = now - timedelta(minutes=minutes)
        start_date = end_date

        sd = None
        ed = None
        if start_date_str:
            try:
                # If start_date >= now - delay we use now - delay
                sd = str_to_utc_datetime(start_date_str, DEFAULT_DATE_FORMAT)
                if sd < start_date:
                    start_date = sd
                else:
                    self.logger.warning(f"The provided start date {start_date_str} is to close or in the future. The default will be used.")

                # If end_date >= now - delay we use now - delay
                if end_date_str:
                    ed = str_to_utc_datetime(end_date_str, DEFAULT_DATE_FORMAT)
                    if ed < end_date:
                        end_date = ed
                    else:
                        self.logger.warning(f"The provided end date {end_date_str} is to close or in the future. The default will be used.")

            except ValueError as e:
                error_message = f"Provided start date {start_date_str} cannot be parsed."
                raise FncClientError(
                    error_type=ErrorType.POLLING_TIME_WINDOW_ERROR,
                    error_message=ErrorMessages.POLLING_TIME_WINDOW_ERROR,
                    error_data={'error_message': error_message, 'error': e},
                    exception=e
                )

        log_start_date = datetime_to_utc_str(start_date)
        log_end_date = datetime_to_utc_str(end_date)
        if not end_date_str:
            self.logger.debug(f"Getting search time window using start_date= {log_start_date} and polling_delay={polling_delay}")
        else:
            self.logger.debug(f"Using a fix search time window (start_date= {log_start_date} and end_date={log_end_date}")

        if end_date < start_date:
            raise FncClientError(
                error_type=ErrorType.POLLING_INVERTED_TIME_WINDOW_ERROR,
                error_message=ErrorMessages.POLLING_INVERTED_TIME_WINDOW_ERROR
            )

        if end_date == start_date:
            raise FncClientError(
                error_type=ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR,
                error_message=ErrorMessages.POLLING_EMPTY_TIME_WINDOW_ERROR,
                error_data={'start_date': start_date, 'end_date': end_date}
            )

        return start_date, end_date

    def get_default_polling_args(self) -> Dict:
        """
        This method returns a dictionary containing all the default arguments for the continuous polling.

        Returns:
            Dict: Dictionary containing the default arguments for the continuous polling
        """
        return {
            'status': 'active',
            'muted': False,
            'muted_rule': False,
            'muted_device': False,
            'sort_by': 'device_ip',
            'sort_order': 'asc',
            'include': 'rules, indicators',
            'limit': POLLING_MAX_DETECTIONS,
            'offset': 0
        }

    def _prepare_continuous_polling(self, context: ApiContext = None, args: Dict = None, limit: int = 0) -> Dict:
        self.logger.info(
            "Preparing arguments for continuously polling Detections.")

        args = args or {}
        polling_args: Dict = None

        if context and context.get_polling_args():
            # Try to get polling arguments from the context and validate them
            try:
                polling_args = context.get_polling_args()
                self._validate_continuous_polling_args(args=polling_args)
                if 'offset' not in polling_args or polling_args['offset'] < 0:
                    polling_args['offset'] = 0
                self.logger.info(
                    "Using arguments received in the context. " +
                    "If this is not the expected behavior, ensure the context's args are cleared before polling."
                )
                return polling_args
            except FncClientError as e:
                self.logger.warning(
                    f'Arguments contained in the context will be ignored due to: \n [{e}]')

        # Getting arguments for the first call
        polling_args: Dict = self.get_default_polling_args()

        if limit:
            lmt = limit if limit < POLLING_MAX_DETECTIONS else POLLING_MAX_DETECTIONS
            polling_args['limit'] = lmt

        polling_delay = args.get('polling_delay', POLLING_DEFAULT_DELAY)
        checkpoint = context.get_checkpoint() if context else None
        start_date_str = args.get('start_date', '')
        end_date_str = args.get('end_date', '')

        start_date, end_date = self._get_and_validate_search_window(
            start_date_str=start_date_str, end_date_str=end_date_str, polling_delay=polling_delay, checkpoint=checkpoint)

        polling_args['created_or_shared_start_date'] = datetime_to_utc_str(
            start_date, DEFAULT_DATE_FORMAT)
        polling_args['created_or_shared_end_date'] = datetime_to_utc_str(
            end_date, DEFAULT_DATE_FORMAT)

        if 'account_uuid' in args:
            polling_args['account_uuid'] = args['account_uuid'],

        muted_rules = str(args.get('pull_muted_rules',
                          polling_args['muted_rule'])).strip().lower()
        if muted_rules == 'all':
            polling_args.pop('muted_rule', None)
        else:
            if muted_rules in ['muted', 'unmuted']:
                muted_rules = 'true' if muted_rules == 'muted' else 'false'
            polling_args['muted_rule'] = muted_rules

        muted_devices = str(args.get('pull_muted_devices',
                            polling_args['muted_device'])).strip().lower()
        if muted_devices == 'all':
            polling_args.pop('muted_device', None)
        else:
            if muted_devices in ['muted', 'unmuted']:
                muted_devices = 'true' if muted_devices == 'muted' else 'false'
            polling_args['muted_device'] = muted_devices

        muted = str(args.get('pull_muted_detections',
                    polling_args['muted'])).strip().lower()
        if muted == 'all':
            polling_args.pop('muted', None)
        else:
            if muted in ['muted', 'unmuted']:
                muted = 'true' if muted == 'muted' else 'false'
            polling_args['muted'] = muted

        status = str(args.get('status', polling_args['status'])).lower()
        if status == 'all':
            status = 'active,resolved'
        polling_args['status'] = status
        polling_args['offset'] = 0

        self._validate_continuous_polling_args(args=polling_args)

        return polling_args

    def _validate_continuous_polling_args(self, args: Dict):
        self.logger.debug("Validating polling arguments.")
        failed = []
        # Verify Sort By is set to device_ip
        sort_by = args.get('sort_by', None)
        if not sort_by or sort_by != 'device_ip':
            failed.append("The sort_by field need to be set to 'device_ip.\n")

        muted_rule = args.get('muted_rule', None)
        if muted_rule and muted_rule not in ['true', 'false']:
            failed.append(
                "The muted_rule allowed values are ['true', 'false'].\n")

        muted_devices = args.get('muted_device', None)
        if muted_devices and muted_devices not in ['true', 'false']:
            failed.append(
                "The muted_devices allowed values are ['true', 'false'].\n")

        muted = args.get('muted', None)
        if muted and muted not in ['true', 'false']:
            failed.append("The muted allowed values are ['true', 'false'].\n")

        status: str = args.get('status', None)
        if not status:
            args['status'] = 'active,resolved'
        elif not all(s in ['active', 'resolved'] for s in status.split(',')):
            failed.append(
                "The status allowed values are ['active', 'resolved'].\n")

        if 'created_or_shared_start_date' not in args or 'created_or_shared_end_date' not in args:
            failed.append(
                "The created_or_shared_start_date and created_or_shared_end_date are required.\n")

        if failed:
            raise FncClientError(
                error_type=ErrorType.POLLING_VALIDATION_ERROR,
                error_message=ErrorMessages.POLLING_VALIDATION_ERROR,
                error_data={'failed': failed}
            )
        else:
            self.logger.info("Polling arguments successfully validated.")

    def _add_detection_rule(self, detection: Dict, rules: Dict, include_description: bool = False, include_signature: bool = False):
        rule = rules[detection['rule_uuid']]

        detection.update({'rule_name': rule['name']})
        detection.update({'rule_severity': rule['severity']})
        detection.update({'rule_confidence': rule['confidence']})
        detection.update({'rule_category': rule['category']})
        detection.update({'rule_primary_attack_id': rule['primary_attack_id']})
        detection.update({'rule_secondary_attack_id': rule['secondary_attack_id']})
        detection.update({'rule_url': f"{self._get_portal_url()}/detections/rules?rule_uuid={rule['uuid']}"})

        if include_description:
            detection.update({'rule_description': rule['description']})

        if include_signature:
            detection.update({'rule_signature': rule['query_signature']})

    def get_entity_information(
        self,
        ctx: ApiContext,
        entity: str,
        account_uuid: str = None,
        fetch_pdns: bool = False,
        fetch_dhcp: bool = False,
        fetch_vt: bool = False,
    ) -> Dict:
        result: Dict = {}
        args: Dict = {'entity': entity}
        if account_uuid:
            args['account_uuid'] = account_uuid

        if not fetch_dhcp and not fetch_pdns and not fetch_vt:
            return result

        self.logger.debug(f'Retrieving information for entity {entity}.')
        if ctx:
            ctx.record_metric(MetricName.ENTITY_ENRICHMENT_REQUESTED)
            cached_record = ctx.get_entity_details_cache().get_record(entity=entity)
            if cached_record:
                self.logger.debug(f"Entity {entity}'s information was found in cache.")
                ctx.record_metric(MetricName.ENTITY_ENRICHMENT_FROM_CACHE)
                return cached_record

        result.update({'entity': entity})

        # Get PDNS/VT/DHCP info if requested
        if fetch_pdns:
            self.logger.debug("Fetching entity's PDNS information.")
            try:
                pdns_data = self.call_endpoint(
                    endpoint=EndpointKey.GET_ENTITY_PDNS, args=args)
                pdns: List = pdns_data.get('passivedns', [])

                result.update({"pdns": pdns})

                self.logger.debug(
                    "Entity's pdns information successfully retrieved.")

            except FncClientError:
                ctx.record_metric(MetricName.FAILED_PDNS_REQUEST)
                # If the request fails for a particular entity, we log it but continue with the execution.
                self.logger.error(f"PDNS information for entity {entity} cannot be added due to:")
                self.logger.error(traceback.format_exc())

        if fetch_dhcp:
            self.logger.debug("Fetching entity's DHCP information.")
            try:
                dhcp_data = self.call_endpoint(
                    endpoint=EndpointKey.GET_ENTITY_DHCP, args=args)
                dhcp: List = dhcp_data.get('dhcp', [])

                result.update({"dhcp": dhcp})

                self.logger.debug(
                    "Entity's DHCP information successfully retrieved.")
            except FncClientError:
                ctx.record_metric(MetricName.FAILED_DHCP_REQUEST)
                # If the request fails for a particular entity, we log it but continue with the execution.
                self.logger.error(f"DHCP information for entity {entity} cannot be added due to:")
                self.logger.error(traceback.format_exc())

        if fetch_vt:
            self.logger.debug("Fetching entity's Virus Total information.")
            try:
                vt_data = self.call_endpoint(
                    endpoint=EndpointKey.GET_ENTITY_VIRUS_TOTAL, args={'entity': entity})
                vt: List = vt_data.get('vt_response', [])

                result.update({"vt": vt})

                self.logger.debug(
                    "Entity's Virus Total information successfully retrieved.")
            except FncClientError:
                ctx.record_metric(MetricName.FAILED_VT_REQUEST)
                # If the request fails for a particular entity, we log it but continue with the execution.
                self.logger.error(f"Virus Total information for entity {entity} cannot be added due to:")
                self.logger.error(traceback.format_exc())

        ctx.get_entity_details_cache().add_record(entity=entity, entityDetails=result)
        return result

    def _get_as_bool(self, value):
        if type(value) is str and value.title() in ['True', 'False']:
            return eval(value.title())

        if type(value) is bool:
            return value

        return False

    def _process_response(
        self,
        ctx: ApiContext,
        response: Dict,
        args: Dict = None
    ):
        # Getting instructions from the arguments
        args = args or {}
        include_description = self._get_as_bool(args.get('include_description'))
        include_signature = self._get_as_bool(args.get('include_signature'))
        include_events = self._get_as_bool(args.get('include_events'))

        fetch_pdns: bool = self._get_as_bool(args.get('include_pdns'))
        fetch_dhcp: bool = self._get_as_bool(args.get('include_dhcp'))
        fetch_vt: bool = self._get_as_bool(args.get('include_vt'))

        fetch_events_pdns: bool = include_events and fetch_pdns
        fetch_events_dhcp: bool = include_events and fetch_dhcp
        fetch_events_vt: bool = include_events and fetch_vt

        fetch_annotations: bool = self._get_as_bool(args.get('include_annotations'))
        fetch_events_annotations: bool = include_events and fetch_annotations

        include_entities = fetch_pdns or fetch_dhcp or fetch_vt or fetch_annotations

        detection_events = {}
        total_events = 0

        dCount = len(response['detections']) if "detections" in response else 0
        if dCount == 0:
            return

        self.logger.info(f"Processing {dCount} retrieved detections.")

        # create a dictionary with the rules to find detection's rule easily
        response['rules'] = dict(
            map(lambda rule: (rule['uuid'], rule),  response['rules']))

        detection: Dict

        self.logger.info(" Enriching detections.")

        # Adding rule's information to the detection
        self.logger.debug("Adding rule's information.")

        for detection in response['detections']:
            self._add_detection_rule(
                detection=detection,
                rules=response['rules'],
                include_description=include_description,
                include_signature=include_signature
            )

        self.logger.info(
            "Rules' information successfully added to the detections.")

        # dictionary holding the arguments required for the annotations bulk request
        annotations_args = {}
        # create a dictionary to match entities to the detection and/or events where they need to be enriched with annotations
        ent_det_map = {}

        # Enrich detection with additional entity's information
        if include_entities:
            self.logger.debug(
                " Enriching detection with additional entity's information.")

            for detection in response['detections']:
                detection_account = detection["account_uuid"] or args["account_uuid"]
                if fetch_annotations and detection_account not in annotations_args:
                    # Preparing information for the arguments required for the annotations request
                    annotations_args[detection_account] = {
                        "account_uuid": detection_account,
                        "entities": []
                    }

                entity = detection['device_ip']
                if entity not in ent_det_map or not ent_det_map[entity]:
                    ent_det_map[entity] = [detection]
                else:
                    ent_det_map[entity].append(detection)

                if fetch_annotations:
                    # Preparing information for the arguments required for the annotations request
                    ent = {}
                    ent["entity"] = entity
                    ent["entity_type"] = "ip"
                    annotations_args[detection_account]["entities"].append(ent)

                # Add the PDNS, DHCP and VT information if requested (Only those that were requested will be retrieved)
                entity_info = self.get_entity_information(
                    ctx=ctx,
                    entity=entity,
                    account_uuid=detection_account,
                    fetch_dhcp=fetch_dhcp,
                    fetch_pdns=fetch_pdns,
                    fetch_vt=fetch_vt
                )
                detection.update(entity_info)

            self.logger.info(
                "Entity's information successfully added to the detections.")

        # Add detection's associated events to the response
        if include_events:
            self.logger.debug("Adding Detection's associated events.")
            failed = 0
            total = 0

            for detection in response['detections']:
                detection_account = detection["account_uuid"] or args["account_uuid"]
                if fetch_annotations and detection_account not in annotations_args:
                    # Preparing information for the arguments required for the annotations request
                    annotations_args[detection_account] = {
                        "account_uuid": detection_account,
                        "entities": []
                    }
                total += 1
                try:
                    ctx.record_metric(MetricName.DETECTION_EVENTS_REQUESTED)
                    events = self._get_detection_events(detection['uuid'])
                    ctx.record_metric(MetricName.DETECTION_EVENTS_RETRIEVED, len(events))
                    total_events = total_events + len(events)
                    detection_events.update({detection['uuid']: events})

                    # Check if any entity's enrichment is required for the events
                    if not include_entities:
                        continue

                    # We need to include some additional entities' information to the associated events
                    self.logger.debug(
                        f" Enriching detection {detection['uuid']}'s associated events with additional entity's information.")
                    for e in events:
                        event: dict = e['event']

                        src_entity_ip = ''
                        src_entity_key = ''
                        dst_entity_ip = ''
                        dst_entity_key = ''

                        # Add the PDNS and DHCP information if requested
                        if ('src' in event and event['src'] not in (None, '')) or ('src_ip' in event and event['src_ip'] not in (None, '')):
                            src_entity_ip = event['src']['ip'] if 'src' in event else event['src_ip']
                            src_entity_key = 'src' if 'src' in event else 'src_ip_enrichments'

                        if ('dst' in event and event['dst'] not in (None, '')) or ('dst_ip' in event and event['dst_ip'] not in (None, '')):
                            dst_entity_ip = event['dst']['ip'] if 'dst' in event else event['dst_ip']
                            dst_entity_key = 'dst' if 'dst' in event else 'dst_ip_enrichments'

                        if include_entities:
                            # Add the PDNS, DHCP and VT information if requested (Only those that were requested will be retrieved)
                            if src_entity_key:
                                entity_info = self.get_entity_information(
                                    ctx=ctx,
                                    entity=src_entity_ip,
                                    account_uuid=detection_account,
                                    fetch_dhcp=fetch_events_dhcp,
                                    fetch_pdns=fetch_events_pdns,
                                    fetch_vt=fetch_events_vt
                                )
                                if src_entity_key in event and event[src_entity_key]:
                                    event[src_entity_key].update(entity_info)

                            if dst_entity_key:
                                entity_info = self.get_entity_information(
                                    ctx=ctx,
                                    entity=dst_entity_ip,
                                    account_uuid=detection_account,
                                    fetch_dhcp=fetch_events_dhcp,
                                    fetch_pdns=fetch_events_pdns,
                                    fetch_vt=fetch_events_vt
                                )
                                if dst_entity_key in event and event[dst_entity_key]:
                                    event[dst_entity_key].update(entity_info)

                        if fetch_events_annotations:
                            # Preparing information for the arguments required for the annotations request
                            if src_entity_key:
                                if src_entity_ip not in ent_det_map or not ent_det_map[src_entity_ip]:
                                    ent_det_map[src_entity_ip] = [event[src_entity_key]]
                                else:
                                    ent_det_map[src_entity_ip].append(event[src_entity_key])

                                ent = {}
                                ent["entity"] = src_entity_ip
                                ent["entity_type"] = "ip"
                                annotations_args[detection_account]["entities"].append(ent)

                            if dst_entity_key:
                                if dst_entity_ip not in ent_det_map or not ent_det_map[dst_entity_ip]:
                                    ent_det_map[dst_entity_ip] = [event[dst_entity_key]]
                                else:
                                    ent_det_map[dst_entity_ip].append(event[dst_entity_key])
                                ent = {}
                                ent["entity"] = dst_entity_ip
                                ent["entity_type"] = "ip"
                                annotations_args[detection_account]["entities"].append(ent)

                except FncClientError:
                    ctx.record_metric(MetricName.DETECTION_EVENTS_FAILED_REQUEST)
                    failed += 1
                    # If the request for associated events fails for a particular detection, we log it but continue with the execution.
                    self.logger.error(f"Detection's events request for {detection['uuid']} failed due to:")
                    self.logger.error(traceback.format_exc())

        if fetch_annotations:
            self.logger.debug("Fetching entities' annotations.")
            # The endpoints implementation expect arguments as string
            for _, ant_args in annotations_args.items():
                ant_args["entities"] = json.dumps(ant_args["entities"])
                annotations_data = self.call_endpoint(endpoint=EndpointKey.GET_ENTITY_ANNOTATIONS, args=ant_args)
                annotations: List = annotations_data.get('entity_annotations', [])

                for annotation in annotations:
                    if "entity" not in annotation or "entity" not in annotation["entity"]:
                        continue
                    annotated_entity = annotation["entity"]["entity"]
                    to_be_updated = ent_det_map[annotated_entity] if annotated_entity in ent_det_map and ent_det_map[annotated_entity] else [
                    ]
                    for det in to_be_updated:
                        det["annotations"] = annotation["annotations"]

        self.logger.info(f"{total - failed} out of {total}) detections were successfully processed.")
        self.logger.info(f"{total_events} associated events were successfully added to the response.")

        response.update({'events': detection_events})

    def _get_detection_events(self, detection_id: str) -> List:
        detection_events = []
        args = {
            'detection_uuid': detection_id,
            'offset': 0,
            'limit': POLLING_MAX_DETECTION_EVENTS
        }

        response = {}
        while 'events' not in response or len(response['events']) == POLLING_MAX_DETECTION_EVENTS:
            try:
                response = self.call_endpoint(
                    endpoint=EndpointKey.GET_DETECTION_EVENTS, args=args.copy(), reduced_log=True)
                args['offset'] = args.get(
                    'offset', 0) + POLLING_MAX_DETECTION_EVENTS
                detection_events.extend(response['events'])
            except FncClientError as e:
                self.logger.error(
                    f"A failure occurs while retrieving detection's associated events for detection {detection_id}.")
                raise e
            finally:
                count = len(detection_events)
                if count:
                    self.logger.debug(
                        f"{count} Detection's associated events were retrieved for detection {detection_id}.")
        return detection_events

    def _get_detections(self, args: Dict) -> Dict:
        args = args or {}
        start_date = args.get('created_or_shared_start_date', '')
        end_date = args.get('created_or_shared_end_date', '')
        offset = args.get('offset', 0)

        if not start_date or not end_date:
            self.logger.warning("No time window was provided. Every detection will be retrieved.")
        else:
            self.logger.info(
                f'Retrieving Detections between {start_date} and {end_date} and offset = {offset}.')

        response = {}

        # Retrieve detections
        response = self.call_endpoint(
            endpoint=EndpointKey.GET_DETECTIONS, args=args)

        return response

    def _check_if_limit_is_overpassed(self, polling_args: Dict, limit):
        polling_args = polling_args.copy()
        polling_args['limit'] = 1

        self.logger.info("Verifying if limit will be overpassed.")

        response = self._get_detections(polling_args)
        if response['total_count'] > limit:
            raise FncClientError(
                error_type=ErrorType.POLLING_LIMIT_OVERPASSED,
                error_message=ErrorMessages.POLLING_LIMIT_OVERPASSED,
                error_data={'limit': limit, 'count': response['total_count']}
            )

    def continuous_polling(self, context: ApiContext = None, args: Dict = None) -> Iterator[Dict]:
        self.logger.info("Starting continuous polling execution.")

        args = args.copy() or {}
        polling_args = {}

        if not context:
            self.logger.warning(
                "No context has been provided. The provided start date ( 7 days ago by default) will be used.")
            self.logger.info(
                "The context is required to keep track of the latest checkpoint to avoid missing or duplicated detections.")

        context = context or ApiContext()
        context.record_metric(MetricName.CONTINUOUS_POLLING_EXECUTION)

        response = {}

        limit = args.get('limit', 0)
        is_limited = limit > 0
        limit_checked = False

        while 'detections' not in response or response['detections']:
            try:
                # Prepare the arguments to be used for requesting detections
                polling_args = self._prepare_continuous_polling(
                    context=context, args=args, limit=limit)

                # Update context with the latest used arguments
                context.update_polling_args(args=polling_args)
                context.update_checkpoint(
                    polling_args['created_or_shared_end_date'])

                if is_limited and not limit_checked:
                    limit_checked = True
                    context.record_metric(MetricName.DETECTIONS_REQUESTED)
                    context.record_metric(MetricName.DETECTIONS_LIMIT_VERIFIED)
                    self._check_if_limit_is_overpassed(polling_args=polling_args, limit=limit)

                # Request detections
                context.record_metric(MetricName.DETECTIONS_REQUESTED)
                response = self._get_detections(polling_args.copy())

                if 'detections' in response and len(response['detections']) > 0:
                    context.record_metric(MetricName.DETECTIONS_RETRIEVED, len(response['detections']))
                    # Process the response enriching it if requested
                    self._process_response(ctx=context, response=response, args=args)

                    offset = polling_args.get('offset', 0)
                    polling_args['offset'] = offset + len(response['detections'])
                    context.update_polling_args(args=polling_args)
                else:
                    self.get_logger().info('No detection retrieved.')
                yield response

            except FncClientError as e:
                error_message = 'Detections cannot be pulled due to:'
                if e.error_type != ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR:
                    self.logger.error(
                        "Detections polling failed. " +
                        "If a context was provided, the arguments used for the latest call will be in the Context's polling_args field.")

                    self.logger.error(f"{error_message} \n {str(e)}")
                    # self.logger.error(traceback.format_exc())
                    raise e
                elif e.error_type != ErrorType.POLLING_LIMIT_OVERPASSED:
                    # At this point, the polling history was cut short to limit the response size and processing time. The already
                    # retrieved piece will be returned and it will be resumed in the next iteration.
                    self.logger.info("The polling history was cut short due to limit being reached. It will be resumed at next iteration.")
                    self.logger.debug(f"{error_message} \n {str(e)}")
                    yield response
                    return
                else:
                    if e.is_request_error(e.error_type):
                        context.record_metric(MetricName.DETECTIONS_FAILED_REQUEST)
                    self.logger.info(f"{error_message} \n {str(e)}")
                    yield response
                    return
            except Exception as e:
                self.logger.error("Detections polling failed unexpectedly.")
                self.logger.error(traceback.format_exc())
                raise FncClientError(
                    error_type=ErrorType.GENERIC_ERROR,
                    error_message=ErrorMessages.GENERIC_ERROR_MESSAGE,
                    error_data={'error': e},
                    exception=e
                )

        self.logger.info(
            "Continuous polling execution successfully completed.")

    def get_splitted_context(self, args: Dict = None) -> Tuple[ApiContext, ApiContext]:
        polling_delay = args.get('polling_delay', POLLING_DEFAULT_DELAY)
        start_date_str = args.get('start_date', '')
        end_date_str = args.get('end_date', '')

        self.logger.info("Splitting the context to extract the history.")
        self.logger.debug(f"Start date= {start_date_str}, End date= {end_date_str}")

        ed = None
        if end_date_str:
            ed = str_to_utc_datetime(end_date_str)

        try:
            start_date, end_date = self._get_and_validate_search_window(
                start_date_str=start_date_str, end_date_str=end_date_str, polling_delay=polling_delay)
        except FncClientError as e:
            if e.error_type == ErrorType.POLLING_EMPTY_TIME_WINDOW_ERROR:
                start_date = e.error_data['start_date']
                end_date = e.error_data['end_date']
            else:
                raise e

        checkpoint = ''
        if not ed or ed > end_date:
            checkpoint = datetime_to_utc_str(
                end_date,
                DEFAULT_DATE_FORMAT
            )
        else:
            now = datetime.now(tz=timezone.utc)
            checkpoint = checkpoint or datetime_to_utc_str(
                now - timedelta(minutes=polling_delay),
                DEFAULT_DATE_FORMAT
            )

        history = {
            'start_date': datetime_to_utc_str(start_date, DEFAULT_DATE_FORMAT),
            'end_date': datetime_to_utc_str(end_date, DEFAULT_DATE_FORMAT),
        }

        self.logger.info("History set to")
        self.logger.debug(f"Start date= {history.get('start_date')}")
        self.logger.debug(f"End date= {history.get('end_date')}")

        history_context = ApiContext()
        history_context.update_history(history=history)

        context = ApiContext()
        context.update_checkpoint(checkpoint=checkpoint)
        context.set_entity_details_cache(history_context.get_entity_details_cache())
        self.logger.info(f"Start checkpoint set to: {checkpoint}")

        return history_context, context

    def poll_history(self, context: ApiContext = None, args: Dict = None, interval: timedelta = timedelta(days=1)) -> Iterator[Dict]:
        # Raise Exception if No Context with History is passed
        if not context or not context.get_history():
            self.logger.error("A splitted context with the history time window is required to pull history")
            raise FncClientError(
                error_type=ErrorType.MISSING_CONTEXT,
                error_message=ErrorMessages.POLLING_MISSING_CONTEXT
            )

        # Copy the Arguments dictionary and update the history time window
        history = context.get_history()

        now = datetime.now(tz=timezone.utc)
        start_date_str = context.get_checkpoint() or history.get('start_date', None)
        end_date_str = history.get('end_date', None)

        start_date = str_to_utc_datetime(start_date_str)
        end_date = str_to_utc_datetime(end_date_str)

        # If the there is no history to pull we return
        if end_date < start_date:
            start_date = end_date
        if end_date == start_date:
            self.get_logger().info(
                f"No history to be polled (start_date= {start_date_str} and end_date= {end_date_str}). ")
            return

        if (
            not start_date or not end_date or
            end_date > now or start_date > now or
            end_date < start_date
        ):
            self.get_logger().warning(
                f"Polling history was called with invalid data (start_date= {start_date_str} and end_date= {end_date_str}). The call will be ignored.")
            return

        self.get_logger().info(f"Polling history from {start_date_str} to {end_date_str}")

        args['start_date'] = start_date_str
        args['end_date'] = end_date_str

        # Required to check if enrichment is needed. If enrichtment is not needed, no extra API call need to be performed
        # and we can retrieve all the detections without caring for the limit
        include_events = self._get_as_bool(args.get('include_events'))

        fetch_pdns: bool = self._get_as_bool(args.get('include_pdns'))
        fetch_dhcp: bool = self._get_as_bool(args.get('include_dhcp'))
        fetch_vt: bool = self._get_as_bool(args.get('include_vt'))

        include_entities = fetch_pdns or fetch_dhcp or fetch_vt
        need_enrichment = include_events or include_entities
        limit = 0

        # Start delta as the lesser of 1 day and the entire history time window
        delta = interval
        if delta > end_date - start_date:
            delta = end_date - start_date

        # If delta is less than 1 hour we do not care about the limit and pull the entire interval
        # otherwise get the limit and the end date for the first piece to pull
        if delta > timedelta(hours=1) and need_enrichment:
            previous_checkpoint = start_date_str

            args['limit'] = args.get('limit', 300)
            ed = start_date + delta
            self.get_logger().debug(f"Enrichment is required so that the limit {limit} will be applied to every iteration.")
        else:
            self.get_logger().debug("Enrichment is not required or the interval is to short. The limit will be ignored.")
            delta = None
            ed = end_date
            args.pop('limit', None)

        # We pull detections one day at a time until the limit is reached
        # If the limit is overpassed in the first piece of 1 day, we start
        # dividing the delta by 2 until we do not overpass the limit or delta
        # is less than 1 hour. At this moment, we pull everything regardless the
        # limit.

        d_count = 0
        is_done = False
        while not is_done:
            try:
                while not is_done and ed <= end_date:
                    # If we haven't yet pulled the entire history, We update the
                    # end_date to pull the next piece
                    context.clear_args()
                    args['end_date'] = datetime_to_utc_str(ed)

                    self.get_logger().info("Polling next piece of the historical data.")
                    count = 0
                    for detections in self.continuous_polling(context=context, args=args.copy()):
                        # we pull detections for the current piece and update the limit appropriately

                        count += len(detections.get('detections', []))
                        yield detections
                    d_count += count
                    limit = args.get('limit', 0)
                    if limit:
                        args['limit'] = limit - count

                    previous_checkpoint = context.get_checkpoint()
                    context.update_checkpoint(args['end_date'])
                    # args['start_date'] = context.get_checkpoint()
                    # history = context.get_history()
                    # history['start_date'] = args['start_date']
                    # context.update_history(history=history)
                    # context.clear_args()

                    is_done = delta != interval
                    delta = interval

                    # If there remaining piece is less than delta we pull the entire remaining interval
                    if ed == end_date:
                        self.get_logger().info("Historical data has been fully retrieved")
                        is_done = True
                    elif end_date - ed <= delta:
                        ed = end_date
                    else:
                        ed = ed + delta

                is_done = True
            except FncClientError as e:
                context.update_checkpoint(previous_checkpoint)
                if e.error_type == ErrorType.POLLING_LIMIT_OVERPASSED:
                    if delta <= timedelta(hours=1):
                        # If the interval is less than 1h we do not split it and stop iteration
                        if d_count > 0:
                            self.get_logger().info(
                                f"The limit of {limit} was overpassed but the interval is to short to split. The iteration will be ended.")
                        else:
                            self.get_logger().info(
                                f"The limit of {limit} was overpassed but the interval is to short to split. Returning a single hour worth of detections.")
                            lmt = args.pop('limit')
                            for detections in self.continuous_polling(context=context, args=args):
                                # we pull detections for the current piece and update the limit appropriately

                                count += len(detections.get('detections', []))
                                yield detections
                            args['limit'] = lmt
                            d_count += count
                        is_done = True
                    elif not d_count or delta == interval:
                        self.get_logger().info(f"The limit of {limit} was overpassed. Splitting the interval in half.")

                        # If we are not done yet and the limit was overpassed we divide the delta in half
                        delta = delta / 2
                        if delta < timedelta(hours=1):
                            # if delta becomes less than 1 hour, we fix it to 1 hour
                            delta = timedelta(hours=1)
                        sd = str_to_utc_datetime(context.get_checkpoint())
                        ed = sd + delta
                    else:
                        self.get_logger().info(
                            f"The limit of {limit} was overpassed with reduced interval. The iteration will be ended.")
                        is_done = True
                else:
                    raise e
        self.get_logger().info("Iteration completed for the history polling.")
