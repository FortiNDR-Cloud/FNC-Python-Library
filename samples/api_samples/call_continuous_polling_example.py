from fnc.api import FncApiClient
from fnc.errors import FncClientError

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
        'start_date': '2024-01-01T00:00:00.000000Z'
    }

    # Split the poling interval in history and current
    h_context, context = client.get_splitted_context(args=polling_args)

    # Using the above method ensure duplications will be avoided since
    # the end date of the history context will be  the checkpoint in the
    # current one
    start_date_str = context.get_checkpoint()

    count = 0

    for response in client.continuous_polling(context=h_context, args=polling_args):
        if 'detections' in response:
            # Do Something...
            count = len(response['detections'])

    # Ensure each iteration start without polling_args in the context
    h_context.clear_args()

    # This is the end of the iteration. It could be called again after waiting for
    # some time. The recommended interval is 5 minutes. The context's checkpoint
    # value will be the next start date it need to be persisted if the context
    # instance will not be available for the next iteration

except FncClientError as e:
    # Any exception will be reported as FncClientError. Specific Error
    # message will be added to the exception depending on its Error Type
    client.get_logger().error(e)
