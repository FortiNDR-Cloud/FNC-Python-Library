from fnc.api import ApiContext, EndpointKey, FncApiClient
from fnc.errors import FncClientError
from fnc.utils import datetime_to_utc_str, str_to_utc_datetime

# Create the FncApiClient with the appropriate API Token
client = FncApiClient(name='sample_client', api_token='api_token')

try:

    polling_args = {
        'polling_delay': 10,
        'status':  'active',
        'pull_muted_detections': 'false',
        'pull_muted_rules':  'false',
        'pull_muted_devices':  'false',
        'include_description': True,
        'include_signature': True,
        'include_pdns': True,
        'include_dhcp': True,
        'include_events': True,
        'limit': 500,
        'start_date': '2024-01-01T00:00:00.000000Z'
    }

    # Split the poling interval in history and current
    h_context, context = client.get_splitted_context(args=polling_args)

    # The history field in the context contains the start and end date
    # to be pulled it can be manually created but using the above method
    # ensure duplications will be avoided since the end date of the history
    # context will be  the checkpoint in the current one
    history = h_context.get_history()
    start_date_str = history.get('start_date', None)
    end_date_str = history.get('end_date', None)

    checkpoint = str_to_utc_datetime(start_date_str)
    end_date = str_to_utc_datetime(end_date_str)

    count = 0

    # The polling args for poll_history should be the same as
    # for the continuous polling
    for response in client.poll_history(context=h_context, args=polling_args):
        if 'detections' in response:
            # Do Something...
            count = len(response['detections'])

    # Ensure each iteration start without polling_args in the context
    h_context.clear_args()

    # This is the end of the iteration. It can be called in a loop until
    # completed or wait for some time between iterations. It only requires
    # the context with the history and checkpoint values

except FncClientError as e:
    # Any exception will be reported as FncClientError. Specific Error
    # message will be added to the exception depending on its Error Type
    client.get_logger().error(e)
