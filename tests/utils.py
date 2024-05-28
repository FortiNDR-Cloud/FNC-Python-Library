
import random
import string
from datetime import datetime, timedelta, timezone

from fnc.api.endpoints import EndpointKey
from fnc.global_variables import METASTREAM_SUPPORTED_EVENT_TYPES
from fnc.utils import datetime_to_utc_str


def get_random_date():
    now = datetime.now(timezone.utc)
    random_date = now - timedelta(days=random.randint(1, 365))
    return datetime_to_utc_str(random_date)


def get_random_ip():
    return f"{random.randint(1,100)}.{random.randint(1,100)}.{random.randint(1,100)}.{random.randint(1,100)}"


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


def get_fake_dns():
    return {
        "resolved": get_random_string(10),
        "first_seen": get_random_date(),
        "last_seen": get_random_date(),
        "record_type": get_random_string(10),
        "source": get_random_string(10),
        "account_uuid": get_random_string(10),
        "sensor_id": get_random_string(10)
    }


def get_fake_dhcp():
    return {
        "customer_id": get_random_string(10),
        "sensor_id": get_random_string(10),
        "ip": get_random_ip(),
        "mac": "11:22:33:44:55:66",
        "lease_start": get_random_date(),
        "lease_end": get_random_date(),
        "hostnames": [get_random_string(10) for i in range(0, random.randint(1, 10))],
        "start_lease_as_long": 1696527437375
    }


def get_fetch_pdns_response(count: int):
    count = count or random.randint(1, 10)
    return {
        "query_type": "ip_address",
        "result_count": count,
        "passivedns": [get_fake_dns() for i in range(0, count)],
    }


def get_fetch_dhcp_response(count: int):
    count = count or random.randint(1, 10)
    return {
        "query_type": "ip_address",
        "result_count": count,
        "dhcp": [get_fake_dhcp() for i in range(0, count)],
    }


def get_empty_detection_events_response():
    return {
        "result_count": 0,
        "total_count": random.randint(1, 10),
        "events": []
    }


def get_fake_detection_events_response(count: int, detections: list):
    count = count or random.randint(1, 10)
    created = 0
    events = []
    i = 0
    while created < count:
        if i < len(detections)-1:
            c = random.randint(created, count)
        else:
            c = count - created
        events.extend([get_fake_event(rule_id=detections[i]['rule_uuid']) for i in range(0, c)])
        created += c
        i += 1

    return {
        "result_count": 1,
        "total_count": 1,
        "events": events,
    }


def get_fake_detection(rule_id: str):
    return {
        "uuid": get_random_string(),
        "rule_uuid": rule_id or get_random_string(),
        "device_ip": get_random_ip(),
        "sensor_id": get_random_string(),
        "account_uuid": get_random_string(),
        "status": random.choice(['active', 'resolved']),
        "muted_rule": random.choice([True, False]),
        "muted": random.choice([True, False]),
        "indicators": [get_random_string(10) for i in range(0, random.randint(1, 10))],
        "event_count": random.randint(0, 999),
        "first_seen": get_random_date(),
        "last_seen":  get_random_date(),
        "created":  get_random_date(),
        "updated":  get_random_date()
    }


def get_fake_rule():
    return {
        "uuid": get_random_string(),
        "account_uuid": get_random_string(),
        "run_account_uuids": [get_random_string()],
        "name": get_random_string(),
        "category": get_random_string(),
        "query_signature": get_random_string(),
        "description": get_random_string(),
        "severity": random.choice(['high', 'medium', 'low']),
        "confidence": random.choice(['high', 'medium', 'low']),
        "enabled": random.choice([True, False]),
        "created_user_uuid": get_random_string(),
        "created": get_random_date(),
        "updated_user_uuid": get_random_string(),
        "updated": get_random_date(),
        "critical_updated": get_random_date(),
        "rule_accounts": [get_random_string()],
        "device_ip_fields": [get_random_string()],
        "source_excludes": []
    }


def get_empty_detections_response():
    return {
        "result_count": 0,
        "total_count": random.randint(1, 10),
        "detections": [],
        "sort_by": get_random_string(10),
        "sort_order": get_random_string(10),
        "offset": random.randint(1, 10),
        "limit": random.randint(1, 10000),
        "rules": []
    }


def get_fake_detections_response(d_count: int, r_count: int):
    d_count = d_count or random.randint(1, 10)
    r_count = r_count or random.randint(1, 10)

    rules = [get_fake_rule() for i in range(0, r_count)]
    detections = [get_fake_detection(random.choice(rules)['uuid']) for i in range(0, d_count)]

    return {
        "result_count": d_count,
        "total_count": d_count,
        "detections": detections,
        "sort_by": get_random_string(10),
        "sort_order": get_random_string(10),
        "offset": random.randint(1, 10),
        "limit": random.randint(1, 10000),
        "rules": rules
    }


def get_fake_event(rule_id: str):
    return {
        "rule_uuid": rule_id,
        "event": {
            "event_type": random.choice(METASTREAM_SUPPORTED_EVENT_TYPES),
            "uuid": get_random_string(10),
            "customer_id": get_random_string(10),
            "sensor_id": get_random_string(10),
            "timestamp": get_random_date(),
            "src": {
                "ip": get_random_ip(),
                "port": random.randint(1, 100),
                "asn": {
                    "asn": random.randint(1, 100),
                    "org": get_random_string(10),
                    "isp": get_random_string(10),
                    "asn_org": get_random_string(10)
                },
                "internal": random.choice([True, False])
            },
            "dst": {
                "ip": get_random_ip(),
                "port": random.randint(1, 100),
                "internal": random.choice([True, False])
            },
            "source": random.choice(METASTREAM_SUPPORTED_EVENT_TYPES),
            "sig_id": random.randint(1, 100),
            "sig_rev": random.randint(1, 100),
            "sig_name": get_random_string(10),
            "sig_category": get_random_string(10),
            "sig_severity": random.randint(1, 3),
            "proto": get_random_string(10),
            "payload": get_random_string(10)
        }
    }
