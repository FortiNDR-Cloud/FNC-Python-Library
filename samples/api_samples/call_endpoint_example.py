from fnc.api import EndpointKey, FncApiClient
from fnc.errors import FncClientError
from fnc.fnc_client import FncClient

client_name = ''
api_token = ''
domain = ''
log_level = None

# Create the FncApiClient with the appropriate API Token
client: FncApiClient = FncClient.get_api_client(name=client_name, domain=domain,
                                                api_token=api_token)

client.get_logger().set_level(level=log_level)

try:
    detection_id = ''
    resolution = ''
    comment = ''

    # Call the specific endpoint (i.e. Resolve_Detection) with the appropriate arguments
    response = client.call_endpoint(EndpointKey.RESOLVE_DETECTION, {
        'detection_id': detection_id, 'resolution': resolution, 'resolution_comment': comment})
    # Do Something with the response...
    client.get_logger().info(response)
except FncClientError as e:
    # Any exception will be reported as FncClientError. Specific Error
    # message will be added to the exception depending on its Error Type
    client.get_logger().error(e)
