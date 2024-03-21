
import random
import string

from fnc.api.endpoints import EndpointKey
from fnc.global_variables import *


def get_random_string(size: int = 10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(10))


def deep_diff(d1: dict, d2: dict) -> bool:
    if len(d1) != len(d2):
        return True

    for k, v in d2.items():
        arg_diff = False

        if (isinstance(d1.get(k), dict) and
                isinstance(v, dict)):
            arg_diff = deep_diff(d1.get(k), v)

        elif (not isinstance(d1.get(k), list) and
              isinstance(v, list)):
            arg_diff = d1.get(k) not in v

        elif (isinstance(d1.get(k), list) and
              isinstance(v, list)):
            arg_diff = any(a not in v for a in d1.get(k))

        else:
            arg_diff = d1.get(k) != v

        if arg_diff:
            return arg_diff

    return arg_diff


def get_random_endpoint_keys(size: int = 0) -> list:
    endpoints = list(EndpointKey._member_map_.keys())
    count = len(endpoints)

    if size <= 0 or size > count-1:
        size = random.randint(1, count-1)

    return random.sample(endpoints, size)


def get_random_endpoint_key() -> EndpointKey:
    endpoints = list(EndpointKey._member_map_.keys())
    key = random.sample(endpoints, 1)
    return EndpointKey(key[0].title())


fake_detection_id = get_random_string(10)
fake_rule_id = get_random_string(10)
fake_event_id = get_random_string(10)
fake_rule_name = get_random_string(10)
fake_rule_severity = get_random_string(10)
fake_rule_confidence = get_random_string(10)
fake_rule_category = get_random_string(10)
fake_rule_description = get_random_string(10)
fake_rule_signature = get_random_string(10)
fake_indicators = [lambda count=i: get_random_string(10) for i in range(1, random.randint(1, 10))]
fake_event_type = random.choice(METASTREAM_SUPPORTED_EVENT_TYPES)
fake_ip = f"{random.randint(1,100)}.{random.randint(1,100)}.{random.randint(1,100)}.{random.randint(1,100)}"
fake_detection = {
    "uuid": fake_detection_id,
    "rule_uuid": fake_rule_id,
    "device_ip": fake_ip,
    "sensor_id": "s1",
    "account_uuid": "a1",
    "status": "active",
    "muted_rule": False,
    "muted": False,
    "indicators": fake_indicators,
    "event_count": 341,
    "first_seen": "2021-02-26T00:51:59.273000Z",
    "last_seen": "2021-08-03T05:38:39.792000Z",
    "created": "2021-02-26T01:15:53.231000Z",
    "updated": "2021-08-03T06:15:44.585000Z"
}
empty_detections_response = {
    "result_count": 0,
    "total_count": 1,
    "detections": [],
    "sort_by": "device_ip",
    "sort_order": "asc",
    "offset": 10000,
    "limit": 10000,
    "rules": []
}
fake_detections_response = {
    "result_count": 1,
    "total_count": 1,
    "detections": [fake_detection],
    "sort_by": "device_ip",
    "sort_order": "asc",
    "offset": 0,
    "limit": 10000,
    "rules": [
        {
            "uuid": fake_rule_id,
            "account_uuid": "a1",
            "run_account_uuids": [
                            "a1"
            ],
            "name": fake_rule_name,
            "category": fake_rule_category,
            "query_signature": fake_rule_signature,
            "description": fake_rule_description,
            "severity": fake_rule_severity,
            "confidence": fake_rule_confidence,
            "enabled": True,
            "created_user_uuid": "u1",
            "created": "2021-09-29T23:18:00.894000Z",
            "updated_user_uuid": "u1",
            "updated": "2021-09-29T23:18:00.894000Z",
            "critical_updated": "2021-09-29T23:18:00.894000Z",
            "rule_accounts": [],
            "device_ip_fields": [
                "DEFAULT"
            ],
            "source_excludes": []
        }
    ]
}
fake_dns = {
    "resolved": get_random_string(10),
    "first_seen": "2023-12-08T00:00:00.000Z",
    "last_seen": "2024-03-11T00:00:00.000Z",
    "record_type": "a",
    "source": "icebrg_dns",
    "account_uuid": "a1",
    "sensor_id": "s1"
}
fake_dhcp = {
    "customer_id": "rzt",
    "sensor_id": 's1',
    "ip": "1.2.3.4",
    "mac": "11:22:33:44:55:66",
    "lease_start": "2023-10-05T17:37:17.375Z",
    "lease_end": "2023-10-05T17:37:17.447Z",
    "hostnames": [
        get_random_string(10)
    ],
    "start_lease_as_long": 1696527437375
}
fake_fetch_pdns = {
    "query_type": "ip_address",
    "result_count": 1000,
    "passivedns": [fake_dns]
}
fake_fetch_dhcp = {
    "query_type": "ip_address",
    "result_count": 6,
    "dhcp": [fake_dhcp]
}

fake_event = {
    "rule_uuid": fake_rule_id,
    "event": {
        "event_type": fake_event_type,
        "uuid": fake_event_id,
        "customer_id": "c1",
        "sensor_id": "s1",
        "timestamp": "2023-11-18T21:20:41.019Z",
        "src": {
            "ip": "1.2.3.4",
            "port": 9999,
            "asn": {
                "asn": 16509,
                "org": get_random_string(10),
                "isp": get_random_string(10),
                "asn_org": get_random_string(10)
            },
            "internal": True
        },
        "dst": {
            "ip": "1.2.3.4",
            "port": 9999,
            "internal": True
        },
        "source": fake_event_type,
        "sig_id": 999999,
        "sig_rev": 2.0,
        "sig_name": get_random_string(10),
        "sig_category": get_random_string(10),
        "sig_severity": 3,
        "proto": "udp",
        "payload": get_random_string(10)
    }
}
empty_detection_events = {
    "result_count": 0,
    "total_count": 1,
    "events": []
}
fake_detection_events = {
    "result_count": 1,
    "total_count": 1,
    "events": [fake_event]
}
