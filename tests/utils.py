
import random
import string

from fnc.api.endpoints import EndpointKey


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
