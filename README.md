# FNC Python Library
version: v1.0.4

----
# Build
Create a pip installable package (currently used by splunk integration)
```shell
python3 setup.py sdist
```
Create a wheel file (currently used by qradar integration)
```shell
python3 setup.py bdist_wheel
```
# Install
Install the package
```shell
pip install dist/com.fortinet.fndrc.integrations.python_client-1.*.tar.gz
```
To install to a specific directory use the `--target`argument.
```shell
pip install --target <directory> dist/com.fortinet.fndrc.integrations.python_client-1.*.tar.gz
```
# Functions
## fetch_events_by_day
Fetch all raw events from metastream for the specified event type in the specified day.  `fetch_events_by_day()` is a generator function that produces a series of events usable in a for-loop or that can be retrieved one at a time with the `next()` function.

```python
from datetime import datetime, timedelta, timezone

from metastream import fetch_events_by_day

day = datetime.now(timezone.utc) - timedelta(days=2)
for events in fetch_events_by_day(name='splunk', event_type='observation', day=day, account_code='chf'):
    print(f'num events: {len(events)}')
```
### Arguments

| Property     | Type     | Required | Default      | Description                                                                      |
|--------------|----------|----------|--------------|----------------------------------------------------------------------------------|
| name         | string   | true     |              | A name that will be used in the s3 user-agent string.                            |
| day          | datetime | true     |              | The day to download events from. Time is ignored if given. Timezone is required. |
| event_type   | string   | true     |              | The event type to download. Possible values are 'observation', 'suricata'        |
| account_code | string   | true     |              | The customer account code.                                                       |
| api_token | string   | true     |              | The customer’s account API Token.
| access_key   | string   | true     |              | AWS access key for authentication.                                               |
| secret_key   | string   | true     |              | AWS secret access key for authentication                                         |
| limit        | int      | false    | no limit     | The maximum number of events to fetch.                                           |
| bucket | string   | true     | fortindr-cloud-metastream  | Bucket from where to retrieve the events
| context      | Context  | false    |              | An object that stores specific session wide data such a metrics and checkpoint.  |
### Return Value
See `fetch_events` return value.
## fetch_events
Fetch raw events from metastream for the specified event type since the specified start date. The start date must be less than a day before and it must have the timezone information or UTC will be assumed by default. `fetch_events()` is a generator function that produces a series of events usable in a for-loop or that can be retrieved one at a time with the `next()` function.
### Example

```python
from metastream import fetch_events, fetch_event_types
from datetime import datetime, timedelta

for events in fetch_events(event_types=fetch_event_types(), account_code='abc', start_date=datetime.now() - timedelta(days=2)):
    # process events ...
    _ = events
```
### Arguments

| Property          | Type         | Required | Default                      | Description                                                                                                    |
|-------------------|--------------|----------|------------------------------|----------------------------------------------------------------------------------------------------------------|
| name              | string       | true     |                              | A name that will be used in the s3 user-agent string.                                                          |
| start_date        | datetime     | false    | current time minus 5 minutes | The time to restrict results based on their timestamp. Must be less than a day. Value must have timezone info. |
| event_type       | string | true    | 'observation' | 'suricata'  | The event type to download. Possible values are observation, suricata.           |
| account_code      | string       | true     |                              | The customer account code.                                                                                     |
| api_token | string   | true     |              | The customer’s account API Token.
| access_key        | string       | true     |                              | AWS access key for authentication.                                                                             |
| secret_access_key | string       | true     |                              | AWS secret access key for authentication                                                                       |
| limit             | int          | false    | no limit                     | The maximum number of events to fetch.                                                                         |
| bucket | string   | true     | fortindr-cloud-metastream  | Bucket from where to retrieve the events
| context           | Context      | false    |                              | An object that stores specific session wide data such a metrics and checkpoint.                                |

### Return value
### Example

```python
response = [
     {'timestamp': '2022-10-16T21:59:53.998000Z',
      'uuid': '24fd131ec-85c9-4af0-b810-c541d2eff5a1',
      'event_type': 'observation',
      'customer_id': 'cid',
      'sensor_id': 'sid',
      'source': 'Fortinet',
      'evidence_start_timestamp': '2022-10-16T21:59:53.998000Z',
      'evidence_end_timestamp': '2022-10-16T22:59:54.814000Z',
      'observation_uuid': 'bf1e1203-ed35-4f22-865d-89e75a1c174a',
      'title': 'TCP Device Enumeration',
      'category': 'relationship',
      'confidence': 'high',
      'src_ip': '1.2.3.4',
      'src_ip_enrichments': {'internal': True,
                             'geo': {'location': {'lat': 37.3541069,
                                                  'lon': -121.955238},
                                     'country': None,
                                     'subdivision': None,
                                     'city': None},
                             'asn': None,
                             'annotations': None},
      'dst_ip': None,
      'dst_ip_enrichments': None,
      'geo_distance': None,
      'sensor_ids': ['chf1'],
      'evidence_iql': 'flow:ip = 1.2.3.4 AND proto = "tcp" AND customer_id = '
                      '"cid" AND timestamp >= t"2022-10-16T21:59:53.998Z" AND '
                      'timestamp <= t"2022-10-16T22:59:54.814Z"',
      'context': '{"Lowest '
                 'ports":["0","1","2","3","4","5","7","9","11","13","15","17","18","19","20","21","23","24","25","27","29","31","33","35","37","38"],"Count '
                 'of distinct hosts":16646,"Duration (seconds) of '
                 'activity":"3600.816","Average duration (seconds) between '
                 'connections":"0.005"}',
      'intel': None,
      'class': 'specific'}
 ]

```
### Definition

| Property          | Type           | Required | Description                                                                        |
|-------------------|----------------|----------|------------------------------------------------------------------------------------|
| events            | array[ Event ] | false    | An array of events is returned from each call until all events have been returned. |
