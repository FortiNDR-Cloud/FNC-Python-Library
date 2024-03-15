# CLIENT DEFAULT
CLIENT_PROTOCOL = 'https'
CLIENT_DEFAULT_DOMAIN = 'icebrg.io'
CLIENT_VERSION = '1.0.0'
CLIENT_NAME = 'FNC_Py_Client'
CLIENT_DEFAULT_USER_AGENT = f"{CLIENT_NAME}-v{CLIENT_VERSION}"

# REQUESTS DEFAULTS
REQUEST_MAXIMUM_RETRY_ATTEMPT = 3
REQUEST_DEFAULT_TIMEOUT = 70
REQUEST_DEFAULT_VERIFY = True

# POLLING DEFAULTS
POLLING_MAX_DETECTIONS = 10000
POLLING_MAX_DETECTION_EVENTS = 1000
POLLING_DEFAULT_DELAY = 10
POLLING_TRAINING_ACCOUNT_ID = 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634'
POLLING_TRAINING_CUSTOMER_ID = 'chg'

# LOGGER DEFAULTS
LOGGER_FORMAT = "%(asctime)s — %(name)s — %(levelname)s — %(message)s"
LOGGER_NAME_PREFIX = "FNC_Client"
LOGGER_MAX_FILE_SIZE = 5*10**7

# OTHER DEFAULTS
DEFAULT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
