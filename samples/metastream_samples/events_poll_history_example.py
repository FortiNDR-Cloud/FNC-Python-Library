import logging
from datetime import datetime, timedelta

from fnc.errors import FncClientError
from fnc.fnc_client import FncClient
from fnc.global_variables import DEFAULT_DATE_FORMAT, METASTREAM_SUPPORTED_EVENT_TYPES
from fnc.metastream.metastream_client import FncMetastreamClient
from fnc.metastream.s3_client import MetastreamContext
from fnc.utils import datetime_to_utc_str, str_to_utc_datetime

api_token = ''
access_key = ''
secret_key = ''
account_code = ''
bucket = ''

# any event_type included in METASTREAM_SUPPORTED_EVENT_TYPES
event_type = ''

client: FncMetastreamClient = FncClient.get_metastream_client(
    name='test_by_chunk',
    access_key=access_key, secret_key=secret_key,
    account_code=account_code, bucket=bucket
)

# Set the logging level. It defaults to INFO
logger = client.get_logger().set_level(level=logging.DEBUG)

try:
    # By default the size of the interval will be 1 day
    interval = timedelta(hours=1)

    # 7 days is the maximum of events historical data that can be retrieved
    star_date_str = '7 days'

    # Split the poling window in history and current
    h_context, context = client.get_splitted_context(
        start_date_str=star_date_str
    )

    total_count = 0

    # Get the start_date and end_date from the history in the context
    history = h_context.get_history(event_type=event_type)
    start_date = history.get('start_date', None)
    end_date = history.get('end_date', None)

    if start_date == end_date:
        # If start_date is the same as the end_date then the whole history
        # was already retrieved
        client.get_logger().info(
            f'{total_count} events were successfully retrieved.')
    else:
        # If not, we poll the next piece of size 'interval'
        for events in client.poll_history(
            context=h_context,
            event_type=event_type,
            interval=interval
        ):
            # Do something ...
            total_count += len(events)

        # After the events are polled the context will be updated and
        # the start_date of the history for the specified event_type
        # will be end_date of the already searched interval
except FncClientError as e:
    # If anything fails, a FncClientError will be raised.
    # Its error_type and error_message will show mor details of the failure
    client.get_logger().error(e)
