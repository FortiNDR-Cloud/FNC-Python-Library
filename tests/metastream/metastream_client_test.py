import random
from datetime import datetime, timedelta, timezone

import pytest

from fnc import FncClient
from fnc.errors import ErrorType, FncClientError
from fnc.global_variables import METASTREAM_DEFAULT_BUCKET, METASTREAM_SUPPORTED_EVENT_TYPES
# from fnc.metastream import fetch_events, fetch_events_by_day
from fnc.metastream.metastream_client import FncMetastreamClient
from fnc.metastream.s3_client import MetastreamContext, S3Client
from tests.utils import get_random_string


def test_get_metastream_client_as_singleton(mocker):

    account_code = 'fake_account_code',
    access_key = 'fake_access_key',
    secret_key = 'fake_secret_key',
    bucket = 'fake_bucket'

    account_code_1 = 'fake_account_code_1',
    access_key_1 = 'fake_access_key_1',
    secret_key_1 = 'fake_secret_key_1',
    bucket_1 = 'fake_bucket_1'

    mocker.patch('fnc.api.api_client.FncApiClient._validate_api_token')

    client = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code,
        access_key=access_key,
        secret_key=secret_key,
        bucket=bucket
    )

    same_client = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code,
        access_key=access_key,
        secret_key=secret_key,
        bucket=bucket
    )

    new_account_code = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code_1,
        access_key=access_key,
        secret_key=secret_key,
        bucket=bucket
    )

    new_access_key = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code_1,
        access_key=access_key_1,
        secret_key=secret_key,
        bucket=bucket
    )

    new_secret_key = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code_1,
        access_key=access_key_1,
        secret_key=secret_key_1,
        bucket=bucket
    )

    new_bucket = FncClient.get_metastream_client(
        name=get_random_string(10),
        account_code=account_code_1,
        access_key=access_key_1,
        secret_key=secret_key_1,
        bucket=bucket_1
    )

    assert client == same_client
    assert client != new_account_code
    assert new_account_code != new_access_key
    assert new_access_key != new_secret_key
    assert new_secret_key != new_bucket


def test_validate_succeed():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_types_len = random.randint(1, len(METASTREAM_SUPPORTED_EVENT_TYPES))
    right_event_types = random.sample(METASTREAM_SUPPORTED_EVENT_TYPES, event_types_len)

    now = datetime.now(tz=timezone.utc)
    before_24_hours = now - timedelta(hours=random.randint(24, 7*24))
    within_same_day_1 = now - timedelta(hours=random.randint(0, now.hour))
    within_same_day_2 = now - timedelta(hours=random.randint(0, now.hour))

    if within_same_day_1 > within_same_day_2:
        dt = within_same_day_1
        within_same_day_1 = within_same_day_2
        within_same_day_2 = dt

    client._validate(event_types=right_event_types, start_date=before_24_hours, end_date=None)
    client._validate(event_types=right_event_types, start_date=within_same_day_1, end_date=within_same_day_2)


def test_validate_failure_unsupported_event_type():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_types_len = random.randint(1, len(METASTREAM_SUPPORTED_EVENT_TYPES))
    wrong_event_types = random.sample(METASTREAM_SUPPORTED_EVENT_TYPES, event_types_len)
    wrong_event_types[random.randint(0, event_types_len-1)] = get_random_string(10)

    now = datetime.now(tz=timezone.utc)
    before_24_hours = now - timedelta(hours=random.randint(24, 7*24))
    within_same_day_1 = now - timedelta(hours=random.randint(0, now.hour))
    within_same_day_2 = now - timedelta(hours=random.randint(0, now.hour))

    if within_same_day_1 > within_same_day_2:
        dt = within_same_day_1
        within_same_day_1 = within_same_day_2
        within_same_day_2 = dt

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=wrong_event_types, start_date=before_24_hours, end_date=None)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=wrong_event_types, start_date=within_same_day_1, end_date=within_same_day_2)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_validate_failure_to_late():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_types_len = random.randint(1, len(METASTREAM_SUPPORTED_EVENT_TYPES))
    right_event_types = random.sample(METASTREAM_SUPPORTED_EVENT_TYPES, event_types_len)

    now = datetime.now(tz=timezone.utc)
    before_7_days = now - timedelta(days=random.randint(8, 365))
    within_same_day_1 = now - timedelta(hours=random.randint(0, now.hour))
    within_same_day_2 = now - timedelta(hours=random.randint(0, now.hour))

    if within_same_day_1 > within_same_day_2:
        dt = within_same_day_1
        within_same_day_1 = within_same_day_2
        within_same_day_2 = dt

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=right_event_types, start_date=before_7_days, end_date=None)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=right_event_types, start_date=within_same_day_1 -
                         timedelta(hours=random.randint(25, 7*24)), end_date=within_same_day_1)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_validate_failure_to_soon():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_types_len = random.randint(1, len(METASTREAM_SUPPORTED_EVENT_TYPES))
    right_event_types = random.sample(METASTREAM_SUPPORTED_EVENT_TYPES, event_types_len)

    now = datetime.now(tz=timezone.utc)
    within_same_day_1 = now - timedelta(hours=random.randint(0, now.hour))
    within_same_day_2 = now - timedelta(hours=random.randint(0, now.hour))
    after_now_1 = now + timedelta(seconds=1)
    after_now_2 = now + timedelta(seconds=random.randint(2, 365*24*60*60))

    if within_same_day_1 > within_same_day_2:
        dt = within_same_day_1
        within_same_day_1 = within_same_day_2
        within_same_day_2 = dt

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=right_event_types, start_date=within_same_day_1, end_date=None)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=right_event_types, start_date=after_now_1, end_date=after_now_2)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_validate_failure_inverted_time_window():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_types_len = random.randint(1, len(METASTREAM_SUPPORTED_EVENT_TYPES))
    right_event_types = random.sample(METASTREAM_SUPPORTED_EVENT_TYPES, event_types_len)

    now = datetime.now(tz=timezone.utc)
    within_same_day_1 = now - timedelta(hours=random.randint(0, now.hour))
    within_same_day_2 = now - timedelta(hours=random.randint(0, now.hour), seconds=1)

    if within_same_day_1 > within_same_day_2:
        dt = within_same_day_1
        within_same_day_1 = within_same_day_2
        within_same_day_2 = dt

    with pytest.raises(FncClientError) as e:
        client._validate(event_types=right_event_types, start_date=within_same_day_2, end_date=within_same_day_1)
    assert e.value.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_get_customer_prefix():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )
    assert client._get_customer_prefix() == f'v1/customer/cust-{account_code}'


def test__prefix_to_datetime():
    account_code = get_random_string(10)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code=account_code,
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    assert isinstance(client._prefix_to_datetime(
        "a/b/date_partition=20221212/"), datetime)
    assert isinstance(client._prefix_to_datetime("20221212"), datetime)
    assert isinstance(client._prefix_to_datetime("20221212//"), datetime)
    assert isinstance(client._prefix_to_datetime("////20221212/"), datetime)
    with pytest.raises(FncClientError) as e:
        client._prefix_to_datetime("/hello/")
    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_UNKNOWN_DATE_PREFIX_FORMAT


def test_fetch_event_types():
    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )
    assert all(e in METASTREAM_SUPPORTED_EVENT_TYPES for e in client.fetch_event_types())
    assert all(e in client.fetch_event_types() for e in METASTREAM_SUPPORTED_EVENT_TYPES)


def test_get_prefixes_succeed(mocker):
    call_1 = [
        'v1/customer/cust-ac/devices/',
        'v1/customer/cust-ac/signals/',
        'v1/customer/cust-ac/s1/'
    ]
    call_2 = [
        'v1/customer/cust-ac/s1/20240310/',
        'v1/customer/cust-ac/s1/20240311/',
        'v1/customer/cust-ac/s1/20240312/',
        'v1/customer/cust-ac/s1/20240313/',
        'v1/customer/cust-ac/s1/20240314/',
        'v1/customer/cust-ac/s1/20240315/',
        'v1/customer/cust-ac/s1/20240316/',
        'v1/customer/cust-ac/s1/20240317/',
        'v1/customer/cust-ac/s1/20240318/',
        'v1/customer/cust-ac/s1/20240319/'
    ]
    call_3 = [
        'v1/customer/cust-ac/s1/20240318/observation/',
        'v1/customer/cust-ac/s1/20240318/suricata/'
    ]

    call_4 = [
        'v1/customer/cust-ac/s1/20240319/observation/',
        'v1/customer/cust-ac/s1/20240319/suricata/'
    ]
    mock_fetch_common_prefixes = mocker.patch('fnc.metastream.s3_client._S3Client.fetch_common_prefixes',
                                              side_effect=[iter(call_1), iter(call_2), iter(call_3), iter(call_4)])

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = 'suricata'
    start_date = datetime(2024, 3, 18, random.randint(0, 23), random.randint(0, 59), random.randint(0, 59), random.randint(1, 999999))
    context = MetastreamContext()

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_common_prefixes = mocker.spy(s3, 'fetch_common_prefixes')
        expected = [
            'v1/customer/cust-ac/s1/20240318/suricata/',
            'v1/customer/cust-ac/s1/20240319/suricata/'
        ]
        i = 0
        end_day = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(seconds=1)
        for prefix in client._get_prefixes(
            s3=s3, event_type=event_type,
            start_day=start_date, end_day=end_day,
            context=context
        ):
            assert prefix == expected[i]
            i += 1

    expected = [
        'v1/customer/cust-ac',
        'v1/customer/cust-ac/s1',
        'v1/customer/cust-ac/s1/20240318',
        'v1/customer/cust-ac/s1/20240319'
    ]

    i = 0
    for c in mock_fetch_common_prefixes.call_args_list:
        assert len(c.args) == 1
        assert c.args[0] == expected[i] or c.args[0] == expected[i] + "/"
        i += 1

    assert spy_fetch_common_prefixes.call_count == 4

    call_3 = [
        'v1/customer/cust-ac/s1/20240316/observation/',
        'v1/customer/cust-ac/s1/20240316/suricata/'
    ]

    mock_fetch_common_prefixes = mocker.patch('fnc.metastream.s3_client._S3Client.fetch_common_prefixes',
                                              side_effect=[iter(call_1), iter(call_2), iter(call_3)])

    event_type = 'observation'
    start_date = datetime(2024, 3, 16, random.randint(0, 23), random.randint(1, 59), random.randint(1, 59), random.randint(1, 999999))

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_common_prefixes = mocker.spy(s3, 'fetch_common_prefixes')
        for prefix in client._get_prefixes(
            s3=s3, event_type=event_type,
            start_day=start_date,
            context=context
        ):
            assert prefix == 'v1/customer/cust-ac/s1/20240316/observation/'

    expected = [
        'v1/customer/cust-ac',
        'v1/customer/cust-ac/s1',
        'v1/customer/cust-ac/s1/20240316'
    ]

    i = 0
    for c in mock_fetch_common_prefixes.call_args_list:
        assert len(c.args) == 1
        assert c.args[0] == expected[i] or c.args[0] == expected[i] + "/"
        i += 1

    assert spy_fetch_common_prefixes.call_count == 3


def test_get_events_from_prefix_no_limit(mocker):
    objs = [
        {'Key': 'f0', 'LastModified': datetime(2024, 3, 18, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f1', 'LastModified': datetime(2024, 3, 18, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f2', 'LastModified': datetime(2024, 3, 18, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f3', 'LastModified': datetime(2024, 3, 19, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f4', 'LastModified': datetime(2024, 3, 19, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f5', 'LastModified': datetime(2024, 3, 19, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f6', 'LastModified': datetime(2024, 3, 20, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f7', 'LastModified': datetime(2024, 3, 20, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f8', 'LastModified': datetime(2024, 3, 20, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f9', 'LastModified': datetime(2024, 3, 21, random.randint(0, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))}
    ]

    to_be_returned = {'f3': ['f3-1', 'f3-2'], 'f4': ['f4-1', 'f4-2'], 'f5': ['f5-1', 'f5-2'],
                      'f6': ['f6-1', 'f6-2'], 'f7': ['f7-1', 'f7-2'], 'f8': ['f8-1', 'f8-2'], 'f9': ['f9-1', 'f9-2']}
    expected = [['f3-1', 'f3-2'], ['f4-1', 'f4-2'], ['f5-1', 'f5-2'], ['f6-1', 'f6-2'], ['f7-1', 'f7-2'], ['f8-1', 'f8-2'], ['f9-1', 'f9-2']]
    limit = 0

    mock_fetch_file_objects = mocker.patch('fnc.metastream.s3_client._S3Client.fetch_file_objects', return_value=objs)
    mock_fetch_gzipped_json_lines_file = mocker.patch(
        'fnc.metastream.s3_client._S3Client.fetch_gzipped_json_lines_file', side_effect=(lambda v: [to_be_returned.get(v)]))

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)
    prefix = 'v1/customer/cust-ac/s1/20240316/observation/'
    context = MetastreamContext()

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_file_objects = mocker.spy(s3, 'fetch_file_objects')
        spy_fetch_gzipped_json_lines_file = mocker.spy(s3, 'fetch_gzipped_json_lines_file')

        i = 0
        for events in client._get_events_from_prefix(
            s3=s3, prefix=prefix,
            limit=limit, num_events=0,
            start_date=start_date, end_date=end_date
        ):
            assert events == expected[i]
            i += 1

    assert len(mock_fetch_file_objects.call_args_list) == 1
    c = mock_fetch_file_objects.call_args_list[0]
    assert len(c.args) == 1
    assert c.args[0] == f'{prefix}v1/'

    expected = ['f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9']
    i = 0
    for c in mock_fetch_gzipped_json_lines_file.call_args_list:
        assert len(c.args) == 1
        assert c.args[0] == expected[i]
        i += 1

    assert spy_fetch_file_objects.call_count == 1
    assert spy_fetch_gzipped_json_lines_file.call_count == 7


def test_get_events_from_prefix_under_limit_partial_file(mocker):
    objs = [
        {'Key': 'f0', 'LastModified': datetime(2024, 3, 18, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f1', 'LastModified': datetime(2024, 3, 18, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f2', 'LastModified': datetime(2024, 3, 18, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f3', 'LastModified': datetime(2024, 3, 19, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f4', 'LastModified': datetime(2024, 3, 19, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f5', 'LastModified': datetime(2024, 3, 19, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f6', 'LastModified': datetime(2024, 3, 20, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f7', 'LastModified': datetime(2024, 3, 20, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f8', 'LastModified': datetime(2024, 3, 20, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f9', 'LastModified': datetime(2024, 3, 21, random.randint(0, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))}
    ]

    to_be_returned = {'f3': ['f3-1', 'f3-2'], 'f4': ['f4-1', 'f4-2'], 'f5': ['f5-1', 'f5-2']}
    expected = [['f3-1', 'f3-2'], ['f4-1', 'f4-2'], ['f5-1']]

    mock_fetch_file_objects = mocker.patch('fnc.metastream.s3_client._S3Client.fetch_file_objects', return_value=objs)
    mock_fetch_gzipped_json_lines_file = mocker.patch(
        'fnc.metastream.s3_client._S3Client.fetch_gzipped_json_lines_file', side_effect=(lambda v: [to_be_returned.get(v)]))

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)
    prefix = 'v1/customer/cust-ac/s1/20240316/observation/'
    context = MetastreamContext()

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_file_objects = mocker.spy(s3, 'fetch_file_objects')
        spy_fetch_gzipped_json_lines_file = mocker.spy(s3, 'fetch_gzipped_json_lines_file')

        i = 0
        for events in client._get_events_from_prefix(
            s3=s3, prefix=prefix,
            limit=5, num_events=0,
            start_date=start_date, end_date=end_date
        ):
            assert events == expected[i]
            i += 1

    assert len(mock_fetch_file_objects.call_args_list) == 1
    c = mock_fetch_file_objects.call_args_list[0]
    assert len(c.args) == 1
    assert c.args[0] == f'{prefix}v1/'

    expected = ['f3', 'f4', 'f5']
    i = 0
    for c in mock_fetch_gzipped_json_lines_file.call_args_list:
        assert len(c.args) == 1
        assert c.args[0] == expected[i]
        i += 1

    assert spy_fetch_file_objects.call_count == 1
    assert spy_fetch_gzipped_json_lines_file.call_count == 3


def test_get_events_from_prefix_under_limit_whole_file(mocker):
    objs = [
        {'Key': 'f0', 'LastModified': datetime(2024, 3, 18, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f1', 'LastModified': datetime(2024, 3, 18, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f2', 'LastModified': datetime(2024, 3, 18, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f3', 'LastModified': datetime(2024, 3, 19, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f4', 'LastModified': datetime(2024, 3, 19, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f5', 'LastModified': datetime(2024, 3, 19, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f6', 'LastModified': datetime(2024, 3, 20, random.randint(0, 8), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f7', 'LastModified': datetime(2024, 3, 20, random.randint(9, 16), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f8', 'LastModified': datetime(2024, 3, 20, random.randint(17, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))},
        {'Key': 'f9', 'LastModified': datetime(2024, 3, 21, random.randint(0, 23), random.randint(0, 59),
                                               random.randint(0, 59), random.randint(1, 999999))}
    ]

    to_be_returned = {'f3': ['f3-1', 'f3-2'], 'f4': ['f4-1', 'f4-2'], 'f5': ['f5-1', 'f5-2']}
    expected = [['f3-1', 'f3-2'], ['f4-1', 'f4-2'], ['f5-1', 'f5-2']]

    mock_fetch_file_objects = mocker.patch('fnc.metastream.s3_client._S3Client.fetch_file_objects', return_value=objs)
    mock_fetch_gzipped_json_lines_file = mocker.patch(
        'fnc.metastream.s3_client._S3Client.fetch_gzipped_json_lines_file', side_effect=(lambda v: [to_be_returned.get(v)]))

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)
    prefix = 'v1/customer/cust-ac/s1/20240316/observation/'
    context = MetastreamContext()

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_file_objects = mocker.spy(s3, 'fetch_file_objects')
        spy_fetch_gzipped_json_lines_file = mocker.spy(s3, 'fetch_gzipped_json_lines_file')

        i = 0
        for events in client._get_events_from_prefix(
            s3=s3, prefix=prefix,
            limit=6, num_events=0,
            start_date=start_date, end_date=end_date
        ):
            assert events == expected[i]
            i += 1

    assert len(mock_fetch_file_objects.call_args_list) == 1
    c = mock_fetch_file_objects.call_args_list[0]
    assert len(c.args) == 1
    assert c.args[0] == f'{prefix}v1/'

    expected = ['f3', 'f4', 'f5']
    i = 0
    for c in mock_fetch_gzipped_json_lines_file.call_args_list:
        assert len(c.args) == 1
        assert c.args[0] == expected[i]
        i += 1

    assert spy_fetch_file_objects.call_count == 1
    assert spy_fetch_gzipped_json_lines_file.call_count == 3


def test_get_events_from_prefix_over_limit(mocker):
    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    start_date = datetime(2024, 3, 19, 0, 0, 0, 000000)
    end_date = datetime(2024, 3, 20, 23, 59, 59, 999999)
    prefix = 'v1/customer/cust-ac/s1/20240316/observation/'
    context = MetastreamContext()

    with S3Client(client.bucket, client.access_key, client.secret_key, client.user_agent, context=context) as s3:
        spy_fetch_file_objects = mocker.spy(s3, 'fetch_file_objects')
        spy_fetch_gzipped_json_lines_file = mocker.spy(s3, 'fetch_gzipped_json_lines_file')

        total = 0
        for events in client._get_events_from_prefix(
            s3=s3, prefix=prefix,
            limit=7, num_events=7,
            start_date=start_date, end_date=end_date
        ):
            total += len(events)

        assert total == 0

    assert spy_fetch_file_objects.call_count == 0
    assert spy_fetch_gzipped_json_lines_file.call_count == 0


def test_fetch_events_time_window_to_long():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = 'observation'
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=random.randint(24, 7*24))
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events(event_type=event_type, limit=12, start_date=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events_unsupported_event_type():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = get_random_string(10)
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=random.randint(0, 23))
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events(event_type=event_type, limit=12, start_date=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events_inverted_time_window():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = 'observation'
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events(event_type=event_type, limit=12, start_date=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events(mocker):
    prefixes = [
        'v1/customer/cust-ac/s1/20240316/observation/',
        'v1/customer/cust-ac/s2/20240316/observation/',
        'v1/customer/cust-ac/s3/20240316/observation/',
        'v1/customer/cust-ac/s4/20240316/observation/',
        'v1/customer/cust-ac/s5/20240316/observation/'
    ]

    expected = [
        [['e1', 'e2']],
        [['e3', 'e4', 'e5']],
        [['e6']],
        [['e8', 'e9', 'e10']],
        [['e11', 'e12']],
    ]
    mock_get_prefixes = mocker.patch('fnc.metastream.metastream_client.FncMetastreamClient._get_prefixes', return_value=prefixes)
    mock_get_events_from_prefix = mocker.patch(
        'fnc.metastream.metastream_client.FncMetastreamClient._get_events_from_prefix', side_effect=expected)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = random.choice(METASTREAM_SUPPORTED_EVENT_TYPES)

    # start_date = datetime(2024, 3, 18, random.randint(0, 23), random.randint(
    #     0, 59), random.randint(0, 59), random.randint(1, 999999), timezone.utc)
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=6)
    context = MetastreamContext()

    # We only check the limit is passed to the _get_events_from_prefix method
    # This method is the one that guaranty that no more than limit events are returned
    # Since this method is mocked we do not check the amount of events returned in this test.
    # That check is tested in the test_get_events_from_prefix test method
    expected_end_day = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(seconds=1)
    limit = random.randint(0, 10)
    i = 0
    for events in client.fetch_events(event_type=event_type, limit=limit, start_date=start_date, context=context):
        assert events == expected[i][0]
        i += 1

    assert mock_get_prefixes.call_count == 1

    for c in mock_get_prefixes.call_args_list:
        assert c.kwargs is not None
        assert event_type == c.kwargs.get('event_type', '')
        assert 'end_day' in c.kwargs and c.kwargs.get('end_day') - expected_end_day < timedelta(seconds=1)
        assert 'start_day' in c.kwargs and start_date.date() == c.kwargs.get('start_day').date()

    assert mock_get_events_from_prefix.call_count == 5

    i = 0
    num_events = 0
    for c in mock_get_events_from_prefix.call_args_list:
        assert c.kwargs is not None
        assert prefixes[i] == c.kwargs.get('prefix', '')
        assert 'limit' in c.kwargs and c.kwargs.get('limit') == limit
        assert 'num_events' in c.kwargs and c.kwargs.get('num_events') == num_events
        assert 'start_date' in c.kwargs and start_date.date() == c.kwargs.get('start_date').date()
        num_events += len(expected[i][0])
        i += 1


def test_fetch_events_by_day_to_late():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = 'observation'
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(days=random.randint(7, 100))
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events_by_day(event_type=event_type, limit=12, day=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events_by_day_unsupported_event_type():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = get_random_string(10)
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=random.randint(0, 23))
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events_by_day(event_type=event_type, limit=12, day=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events_by_day_to_soon():

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = 'observation'
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
    context = MetastreamContext()

    total = 0
    with pytest.raises(FncClientError) as e:
        for events in client.fetch_events_by_day(event_type=event_type, limit=12, day=start_date, context=context):
            total += len(events)
    assert total == 0

    ex = e.value
    assert ex.error_type == ErrorType.EVENTS_FETCH_VALIDATION_ERROR


def test_fetch_events_by_day(mocker):
    prefixes = [
        'v1/customer/cust-ac/s1/20240316/observation/',
        'v1/customer/cust-ac/s2/20240316/observation/',
        'v1/customer/cust-ac/s3/20240316/observation/',
        'v1/customer/cust-ac/s4/20240316/observation/',
        'v1/customer/cust-ac/s5/20240316/observation/'
    ]

    expected = [
        [['e1', 'e2']],
        [['e3', 'e4', 'e5']],
        [['e6']],
        [['e8', 'e9', 'e10']],
        [['e11', 'e12']],
    ]
    mock_get_prefixes = mocker.patch('fnc.metastream.metastream_client.FncMetastreamClient._get_prefixes', return_value=prefixes)
    mock_get_events_from_prefix = mocker.patch(
        'fnc.metastream.metastream_client.FncMetastreamClient._get_events_from_prefix', side_effect=expected)

    client: FncMetastreamClient = FncMetastreamClient(
        name='Test',
        account_code='ac',
        access_key='access_key',
        secret_key='secret_key',
        bucket=METASTREAM_DEFAULT_BUCKET
    )

    event_type = random.choice(METASTREAM_SUPPORTED_EVENT_TYPES)
    # start_date = datetime(2024, 3, 18, random.randint(0, 23), random.randint(
    #     0, 59), random.randint(0, 59), random.randint(1, 999999), timezone.utc)
    start_date = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=random.randint(24, 7*24))
    context = MetastreamContext()

    # We only check the limit is passed to the _get_events_from_prefix method
    # This method is the one that guaranty that no more than limit events are returned
    # Since this method is mocked we do not check the amount of events returned in this test.
    # That check is tested in the test_get_events_from_prefix test method
    limit = random.randint(0, 10)
    i = 0
    for events in client.fetch_events_by_day(event_type=event_type, limit=limit, day=start_date, context=context):
        assert events == expected[i][0]
        i += 1

    assert mock_get_prefixes.call_count == 1

    for c in mock_get_prefixes.call_args_list:
        assert c.kwargs is not None
        assert event_type == c.kwargs.get('event_type', '')
        assert 'end_day' not in c.kwargs
        assert 'start_day' in c.kwargs and start_date.date() == c.kwargs.get('start_day').date()

    assert mock_get_events_from_prefix.call_count == 5

    i = 0
    num_events = 0
    for c in mock_get_events_from_prefix.call_args_list:
        assert c.kwargs is not None
        assert prefixes[i] == c.kwargs.get('prefix', '')
        assert 'limit' in c.kwargs and c.kwargs.get('limit') == limit
        assert 'num_events' in c.kwargs and c.kwargs.get('num_events') == num_events
        assert 'start_date' not in c.kwargs or not c.kwargs.get('start_date')
        num_events += len(expected[i][0])
        i += 1
